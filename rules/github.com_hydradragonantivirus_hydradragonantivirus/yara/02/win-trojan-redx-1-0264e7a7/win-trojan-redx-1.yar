rule Win_Trojan_RedX_1
{
strings:
	$a0 = { 9c1904bf00018a0788058b47018945 }


condition:
	$a0
}