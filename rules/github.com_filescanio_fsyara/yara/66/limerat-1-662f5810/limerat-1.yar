rule LimeRAT_1 : hardened
{
	meta:
		description = "Detects Lime RAT malware samples based on the strings matched"
		author = "RustyNoob619"
		source = "https://valhalla.nextron-systems.com/info/rule/MAL_LimeRAT_Mar23"
		hash = "b62f72df91cffe7861b84a38070e25834ca32334bea0a0e25274a60a242ea669"
		original_yara_name = "LimeRAT"
		ruleset = "EXE_RAT_LimeRAT.yara"
		repository = "RustyNoob-619/YARA"
		source_url = "https://github.com/RustyNoob-619/YARA/blob/b4d14356c117458127705ab545de47cef2769a78/Rules/EXE_RAT_LimeRAT.yara"
		score = 75

	strings:
		$main = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 20 00 2f 00 74 00 6e 00 20 00 4c 00 69 00 6d 00 65 00 52 00 41 00 54 00 2d 00 41 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00}
		$cmd1 = {46 00 6c 00 6f 00 6f 00 64 00 21 00}
		$cmd2 = {21 00 50 00 53 00 65 00 6e 00 64 00}
		$cmd3 = {21 00 50 00 53 00 74 00 61 00 72 00 74 00}
		$cmd4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}
		$cmd5 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00}
		$cmd6 = {5f 00 55 00 53 00 42 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00}
		$cmd7 = {5f 00 50 00 49 00 4e 00 20 00 45 00 72 00 72 00 6f 00 72 00 21 00}

	condition:
		uint16( 0 ) == 0x5A4D and $main and 4 of ( $cmd* )
}