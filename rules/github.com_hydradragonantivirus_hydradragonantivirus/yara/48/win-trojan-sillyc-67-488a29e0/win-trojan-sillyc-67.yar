rule Win_Trojan_SillyC_67
{
strings:
	$a0 = { 2189c3b803e98826990028069a00b43fb903005acd21b8 }


condition:
	$a0
}