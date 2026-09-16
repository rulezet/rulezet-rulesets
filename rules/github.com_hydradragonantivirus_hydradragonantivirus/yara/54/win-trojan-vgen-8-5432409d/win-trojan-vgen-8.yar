rule Win_Trojan_VGEN_8
{
strings:
	$a0 = { 97b9040051e87d0059e2f9be5e02b9b3035706e369b40fcd1032e4cd1033ffb800b88ec08bd733c0fcac3c2072 }


condition:
	$a0
}