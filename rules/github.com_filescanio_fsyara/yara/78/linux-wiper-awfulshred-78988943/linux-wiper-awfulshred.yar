rule Linux_Wiper_AWFULSHRED : hardened
{
	meta:
		description = "Detects AWFULSHRED wiper used against Ukrainian ICS"
		author = "mmuir@cadosecurity.com"
		date = "2022-04-12"
		license = "Apache License 2.0"
		hash = "bcdf0bd8142a4828c61e775686c9892d89893ed0f5093bdc70bde3e48d04ab99"
		score = 60

	strings:
		$isBash = {2f 62 69 6e 2f 62 61 73 68}
		$a1 = {64 65 63 6c 61 72 65 20 2d 72}
		$a2 = {62 61 73 68 5f 68 69 73 74 6f 72 79}
		$a3 = {62 73 3d 31 6b 20 69 66 3d 2f 64 65 76 2f 75 72 61 6e 64 6f 6d 20 6f 66 3d}
		$a4 = {73 79 73 74 65 6d 64}
		$a5 = {61 70 61 63 68 65 20 68 74 74 70 20 73 73 68}
		$a6 = {73 68 72 65 64}
		$var1 = {69 77 6c 6a 7a 66 6b 67}
		$var2 = {79 72 6b 64 72 72 75 65}
		$var3 = {61 67 7a 65 72 6c 79 66}
		$var4 = {72 67 67 79 67 7a 6e 79}
		$var5 = {7a 75 62 7a 67 6e 76 70}

	condition:
		$isBash and 3 of ( $a* ) and 4 of ( $var* )
}