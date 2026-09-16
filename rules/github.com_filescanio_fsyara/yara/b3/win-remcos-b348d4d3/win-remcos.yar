rule win_remcos : rat hardened
{
	meta:
		author = "CERT Polska"

	strings:
		$convenient1 = {20 2a 20 42 72 65 61 6b 69 6e 67 2d 53 65 63 75 72 69 74 79 2e 4e 65 74}
		$convenient2 = {20 2a 20 52 45 4d 43 4f 53 20 76}
		$convenient3 = {53 45 54 54 49 4e 47 53}
		$convenient4 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a}
		$convenient5 = {4f 6e 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64}
		$convenient6 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43}
		$convenient7 = {52 65 6d 63 6f 73 20 41 67 65 6e 74 20 69 6e 69 74 69 61 6c 69 7a 65 64}

	condition:
		3 of ( $convenient* )
}