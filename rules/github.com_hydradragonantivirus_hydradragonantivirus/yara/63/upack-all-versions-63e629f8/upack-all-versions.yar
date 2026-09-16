import "pe"
rule Upack_all_versions : Dwing
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 74 1F 51 56 97 FF D1 93 AC 84 C0 75 FB 38 06 74 EA 8B C6 79 05 46 33 C0 66 AD 50 53 FF D5 AB EB E7 C3 }
		$a1 = { 74 30 51 56 97 FF D1 93 AC 84 C0 75 FB 38 06 74 EA 8B C6 79 05 46 33 C0 66 AD 50 53 FF D5 AB EB E7 33 C0 40 8D 54 85 00 FF 16 13 C0 3B C1 72 F4 2B C1 C3 }
		$a2 = { E2 FA 5B 03 DA 43 59 89 5D 0C 56 8B F7 2B F3 F3 A4 AC 5E B1 80 AA 3B 7E 2C 73 03 FF 66 28 58 8B 4E 30 5F E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 1C 2B C7 AB E2 E5 8B 5E 34 8B 76 38 46 AD ?? C0 0F 84 }
				$a3 = { 8B 5E 28 56 52 8B 76 2C 46 AD 85 C0 5A 74 22 03 C2 52 56 97 FF 53 FC 95 AC 84 C0 75 FB 38 06 74 E7 8B C6 79 05 46 33 C0 66 AD 50 55 FF 13 AB EB E7 59 5F 8B 49 44 E3 0D 33 C0 AC 3C 04 72 0C 03 F8 01 17 E2 F3 61 E9 }
	condition:
		(
		((pe.linker_version.major == 0) and (pe.linker_version.minor == 01 )) or 
		((pe.linker_version.major == 0) and (pe.linker_version.minor == 41 )) or 		((pe.linker_version.major == 0) and (pe.linker_version.minor == 48 )) or 		((pe.linker_version.major == 0) and (pe.linker_version.minor == 50 )) or 		((pe.linker_version.major == 0) and (pe.linker_version.minor == 51 )) or 		((pe.linker_version.major == 75) and (pe.linker_version.minor == 69 )) or 		((pe.linker_version.major == 0) and (pe.linker_version.minor == 53 )) or 		((pe.linker_version.major == 0) and (pe.linker_version.minor == 57 )) or 		((pe.linker_version.major == 76) and (pe.linker_version.minor == 111 )) or 		((pe.linker_version.major == 80) and (pe.linker_version.minor == 255 )) 		
		) and
				any of them
		 
}