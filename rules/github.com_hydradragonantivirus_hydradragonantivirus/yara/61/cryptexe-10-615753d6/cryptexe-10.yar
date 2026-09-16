import "pe"
rule _CryptEXE_10_
{
	meta:
		description = "CryptEXE 1.0"
	strings:
		$0 = {50 FC 0E 1F 1E 07 BA 37 03 B4 09 CD 21 33 C9 8B FA 57 B4 00 CD 16 3C 1B 75 05 E8 E0 02 EB 35 3C 0D 74 36 3C 08 75 0A 80 F9 00 74 E6 FE C9 4F EB E1 3C 20 72 DD 3C EF 77 D9 80 F9 14 74 D4 3C 61 72 06 3C 7A 77 02 2C 20 AA FE C1 EB C5 BA 7E 03}
	condition:
		$0 at pe.entry_point
}