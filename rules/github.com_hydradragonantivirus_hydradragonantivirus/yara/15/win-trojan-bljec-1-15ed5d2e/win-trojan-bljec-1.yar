rule Win_Trojan_Bljec_1
{
strings:
	$a0 = { 9090b98000be8000bf7ffff3a4 }


condition:
	$a0
}