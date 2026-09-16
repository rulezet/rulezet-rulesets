rule MAL_Remcos_strings : hardened
{
	meta:
		description = "Matches strings found in Remcos RAT samples."
		last_modified = "2024-03-20"
		author = "@petermstewart"
		DaysofYara = "80/100"
		sha256 = "b3d7fad59a0ae75ffef9e05f47fc381b4adb716c498106482492e56c1b4370a7"
		sha256 = "9046b2e6ce92647474048c30439ab21ee69a46f6067dbaff67de729644120fad"
		ruleset = "MAL_C2_Remcos.yar"
		repository = "100DaysofYARA/2024"
		source_url = "https://github.com/100DaysofYARA/2024/blob/7df92fafb900e3f148d927ac8dd68bfeaea0c332/petermstewart/MAL_C2_Remcos.yar"
		license = "MIT License"
		score = 75

	strings:
		$a = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a}
		$b1 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43 3a 20}
		$b2 = {55 6e 61 62 6c 65 20 74 6f 20 64 65 6c 65 74 65 3a 20}
		$b3 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 6e 61 6d 65 20 66 69 6c 65 21}
		$b4 = {42 72 6f 77 73 69 6e 67 20 64 69 72 65 63 74 6f 72 79 3a 20}
		$b5 = {4f 66 66 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$b6 = {4f 6e 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$b7 = {5b 43 68 72 6f 6d 65 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 66 6f 75 6e 64 2c 20 63 6c 65 61 72 65 64 21 5d}
		$b8 = {5b 46 69 72 65 66 6f 78 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 63 6c 65 61 72 65 64 21 5d}
		$b9 = {43 6c 65 61 72 65 64 20 61 6c 6c 20 62 72 6f 77 73 65 72 20 63 6f 6f 6b 69 65 73 2c 20 6c 6f 67 69 6e 73 20 61 6e 64 20 70 61 73 73 77 6f 72 64 73 2e}
		$b10 = {5b 46 6f 6c 6c 6f 77 69 6e 67 20 74 65 78 74 20 68 61 73 20 62 65 65 6e 20 70 61 73 74 65 64 20 66 72 6f 6d 20 63 6c 69 70 62 6f 61 72 64 3a 5d}
		$b11 = {5b 45 6e 64 20 6f 66 20 63 6c 69 70 62 6f 61 72 64 20 74 65 78 74 5d}
		$b12 = {4f 70 65 6e 43 61 6d 65 72 61}
		$b13 = {43 6c 6f 73 65 43 61 6d 65 72 61}

	condition:
		uint16( 0 ) == 0x5a4d and $a and 10 of ( $b* )
}