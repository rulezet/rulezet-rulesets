rule Linux_Wiper_SOLOSHRED : hardened
{
	meta:
		description = "Detects SOLOSHRED wiper used against Ukrainian ICS"
		author = "mmuir@cadosecurity.com"
		date = "2022-04-12"
		license = "Apache License 2.0"
		hash = "87ca2b130a8ec91d0c9c0366b419a0fce3cb6a935523d900918e634564b88028"
		score = 60

	strings:
		$a = {70 72 69 6e 74 65 6e 76 20 7c 20 67 72 65 70 20 2d 69 20 22 6f 72 61 22}
		$b = {73 68 72 65 64}
		$c = {2d 2d 6e 6f 2d 70 72 65 73 65 72 76 65 2d 72 6f 6f 74}
		$d = {2f 64 65 76 2f 64 73 6b}
		$e = {24 28 6c 73 20 2f 29}

	condition:
		all of them
}