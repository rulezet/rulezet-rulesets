rule Win_Trojan_Peed_101
{
strings:
	$a0 = { 39d80f8e01000000c358e9[0-128]b44000505050505050 }


condition:
	$a0
}