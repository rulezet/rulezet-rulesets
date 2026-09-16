rule Win_Trojan_NumberofBeast_2
{
strings:
	$a0 = { 8bd6b102b43fcd218ad186cdbffe }


condition:
	$a0
}