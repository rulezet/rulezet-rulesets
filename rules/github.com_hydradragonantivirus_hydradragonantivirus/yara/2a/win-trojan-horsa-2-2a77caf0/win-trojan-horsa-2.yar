rule Win_Trojan_Horsa_2
{
strings:
	$a0 = { aa1ee80000582d120033d2b91000f7f10bd27403e98b038c }


condition:
	$a0
}