rule Win32_Trojan_Packed_RedLineStealer : hardened
{
	meta:
		description = "Identifies a loader used to deploy RedLine Stealer"
		author = "Netskope Threat Labs"
		reference = "4d77e265722624b5d4d1841d45c7c677"
		ruleset = "Win32_Trojan_RedLineStealer.yar"
		repository = "netskopeoss/NetskopeThreatLabsIOCs"
		source_url = "https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/52c780db6106d0c0e8deb04653e036cdd4408e56/Malware/RedLine%20Stealer/Yara/Win32_Trojan_RedLineStealer.yar"
		license = "MIT License"
		score = 75

	strings:
		$str00 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}
		$str01 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00}
		$api01 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$api02 = {53 65 6e 64 4d 65 73 73 61 67 65 41}
		$api03 = {50 6f 73 74 4d 65 73 73 61 67 65 41}
		$asm00 = { 8a 8? ?? ?? ?? ?? 30 04 ?e 46 }
		$asm01 = { 8a 8? ?? ?? ?? ?? 30 04 3e e8 }

	condition:
		uint16( 0 ) == 0x5a4d and 1 of ( $str* ) and 2 of ( $api* ) and 1 of ( $asm* )
}