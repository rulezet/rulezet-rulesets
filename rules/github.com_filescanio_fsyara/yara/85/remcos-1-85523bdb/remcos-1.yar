rule Remcos_1 : hardened
{
	meta:
		author = "@neonprimetime"
		description = "Remcos RAT"
		original_yara_name = "Remcos"
		ruleset = "remcos.yar"
		repository = "kevthehermit/RATDecoders"
		source_url = "https://github.com/kevthehermit/RATDecoders/blob/d675ba1c06e6dd8365149c9ee8a8db1a6e5e508e/malwareconfig/yaraRules/remcos.yar"
		license = "MIT License"
		score = 75

	strings:
		$a1 = {53 6f 66 74 77 61 72 65 5c 52 65 6d 63 6f 73}
		$a2 = {5c 72 65 6d 63 6f 73 5c}
		$a3 = {52 45 4d 43 4f 53 20 76}
		$b1 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$b2 = {43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 43 26 43}
		$b3 = {53 63 72 65 65 6e 73 68 6f 74 73}
		$b4 = {4f 70 65 6e 43 61 6d 65 72 61}
		$b5 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43}
		$b6 = {49 6e 69 74 69 61 6c 69 7a 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 43 26 43}
		$b7 = {63 6c 65 61 72 65 64 21 5d}
		$b8 = {45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30}
		$b9 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43}
		$b10 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 3a 25 30 33 69}
		$b11 = {5b 46 69 72 65 66 6f 78 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 43 6c 65 61 72 65 64 21 5d}
		$b12 = {6c 69 63 65 6e 63 65 5f 63 6f 64 65 2e 74 78 74}

	condition:
		1 of ( $a* ) or 3 of ( $b* )
}