rule Win_Trojan_Adri_1
{
strings:
	$a0 = { 0c00b44cb976032e8a0581ff2900720532c42e8805d0c402e047e2 }


condition:
	$a0
}