rule EICAR_UTF16_Plaintext : hardened
{
	meta:
		author = "filescan.io"
		description = "Detects the EICAR test string stored as UTF-16, which the ASCII-only EICAR rules miss"
		score = 75

	strings:
		$a = {58 00 35 00 4f 00 21 00 50 00 25 00 40 00 41 00 50 00 5b 00 34 00 5c 00 50 00 5a 00 58 00 35 00 34 00 28 00 50 00 5e 00 29 00 37 00 43 00 43 00 29 00 37 00 7d 00 24 00 45 00 49 00 43 00 41 00 52 00 2d 00 53 00 54 00 41 00 4e 00 44 00 41 00 52 00 44 00 2d 00 41 00 4e 00 54 00 49 00 56 00 49 00 52 00 55 00 53 00 2d 00 54 00 45 00 53 00 54 00 2d 00 46 00 49 00 4c 00 45 00 21 00 24 00 48 00 2b 00 48 00 2a 00}

	condition:
		any of them
}