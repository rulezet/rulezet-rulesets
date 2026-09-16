rule Win_Trojan_FRODO_1
{
strings:
	$a0 = { e621fb33dbb90100ebfe49750b33ff43e80a00e80700b104b020e620cfb92800e82600abab }


condition:
	$a0
}