rule Win_Trojan_Crypt_213
{
strings:
	$a0 = { 57c7c772afb4df8d3d5fba581affcf0facf7f20fbdfef7c75cdc3027 }

	$a1 = { 5741524e49c8473ae12d7a }


condition:
	$a0 and $a1
}