rule Win_Trojan_Small_4447
{
strings:
	$a0 = { 50b8ff??400081c001000000010424686009000050e8 }


condition:
	$a0
}