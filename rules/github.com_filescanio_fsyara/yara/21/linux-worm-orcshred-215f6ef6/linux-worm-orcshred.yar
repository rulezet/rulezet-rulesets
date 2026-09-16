rule Linux_Worm_ORCSHRED : hardened
{
	meta:
		description = "Detects ORCSHRED worm used in attacks on Ukrainian ICS"
		author = "mmuir@cadosecurity.com"
		date = "2022-04-12"
		license = "Apache License 2.0"
		hash = "43d07f28b7b699f43abd4f695596c15a90d772bfbd6029c8ee7bc5859c2b0861"
		score = 60

	strings:
		$a = {69 73 5f 6f 77 6e 65 72}
		$b = {53 74 61 72 74 20 6d 6f 73 74 20 73 65 63 75 72 69 74 79 20 6d 6f 64 65 21}
		$c = {63 68 65 63 6b 5f 73 6f 6c 61 72 69 73}
		$d = {77 73 6f 6c 2e 73 68}
		$e = {77 6f 62 66 2e 73 68}
		$f = {64 69 73 6f 77 6e}
		$g = {2f 76 61 72 2f 6c 6f 67 2f 74 61 73 6b 73}

	condition:
		4 of them
}