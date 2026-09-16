rule LZSS
{
		meta:
		author="_pusher_"
		date = "2016-09"
		description = "LZSS Decompression"
	strings: 
				$a0 = { 53 56 57 89 D7 89 C6 01 CA 31 C0 83 C6 04 31 C9 AC 88 C7 B3 08 39 FA 76 28 D0 EF 73 03 A4 EB 1B 66 AD 88 E1 C0 E9 04 66 83 E1 0F 66 83 C1 02 66 25 FF 0F 56 89 FE 29 C6 F3 A4 5E FE CB 75 D6 EB CF 5F 5E 5B C3 }
	condition:
		$a0
}