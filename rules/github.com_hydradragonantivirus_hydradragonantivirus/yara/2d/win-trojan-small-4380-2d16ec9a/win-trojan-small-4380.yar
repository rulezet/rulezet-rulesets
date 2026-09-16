rule Win_Trojan_Small_4380
{
strings:
	$a0 = { 50b8ff1b420081c001000000010424 }


condition:
	$a0
}