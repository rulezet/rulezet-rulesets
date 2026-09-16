rule RijnDael_AES_LONG_inv
{	meta:
		author = "edeca"
		description = "RijnDael AES"
		date = "2019-10"
	strings:
		$c0 = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB 7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB }
	condition:
		$c0
}