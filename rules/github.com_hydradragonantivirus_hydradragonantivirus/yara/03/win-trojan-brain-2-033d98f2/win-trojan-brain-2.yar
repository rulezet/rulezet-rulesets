rule Win_Trojan_Brain_2
{
strings:
	$a0 = { fba0067ca2097c8b0e077c890e0a7ce8 }


condition:
	$a0
}