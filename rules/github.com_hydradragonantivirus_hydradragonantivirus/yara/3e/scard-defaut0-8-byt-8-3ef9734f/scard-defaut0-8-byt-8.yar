rule Scard_DEFAUT0__8_byt_8_
{
strings:
	$a0 = { ad9f61fefa20ce63 }

condition:
	$a0
}