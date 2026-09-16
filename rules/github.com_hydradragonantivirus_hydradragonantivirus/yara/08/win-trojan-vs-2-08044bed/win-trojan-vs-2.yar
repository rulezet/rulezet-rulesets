rule Win_Trojan_VS_2
{
strings:
	$a0 = { e86702baba06b91c00b440e85c028b16ae068b0eb006f7c20080750481c200c8b80157e844 }


condition:
	$a0
}