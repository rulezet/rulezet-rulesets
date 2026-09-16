rule Win_Trojan_Dir_4
{
strings:
	$a0 = { 6c032e8c066e03c7068400d4018c0e86 }


condition:
	$a0
}