rule Win_Trojan_Corea_1
{
strings:
	$a0 = { b91c00ba4607e86afdb80042595acd21b440b9460733d2cd21b800428b16ae078b0eb007cd21 }


condition:
	$a0
}