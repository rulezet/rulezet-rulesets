import "pe"
rule Mal_Backdoor_Win32_SystemBC_2021 : hardened
{
	meta:
		description = "Detects Win32 SystemBC RAT"
		author = " Blackberry Threat Research team "
		date = "2021-01-06"
		score = 40

	strings:
		$x1 = {28 22 69 6e 63 6f 6e 73 69 73 74 65 6e 74 20 49 4f 42 20 66 69 65 6c 64 73 22 2c 20 73 74 72 65 61 6d 2d 3e 5f 70 74 72 20 2d 20 73 74 72 65 61 6d 2d 3e 5f 62 61 73 65 20 3e 3d 20 30 29}
		$x2 = {66 3a 5c 76 73 37 30 62 75 69 6c 64 73 5c 33 30 37 37 5c 76 63 5c 63 72 74 62 6c 64 5c 63 72 74 5c 73 72 63 5c 73 70 72 69 6e 74 66 2e 63}
		$x3 = {79 3a 5c 74 65 73 74 34 5c 65 39 33 5c 44 65 62 75 67 5c 65 39 33 2e 70 64 62}
		$x4 = {37 20 35 36 20 37 35 36 20 37 35 36 37 20 35}

	condition:
		uint16( 0 ) == 0x5a4d and pe.imphash ( ) == "18c64388b1cd2a51505e0d24460c1ed7" and pe.number_of_sections == 6 and filesize < 800KB and 3 of ( $x* )
}