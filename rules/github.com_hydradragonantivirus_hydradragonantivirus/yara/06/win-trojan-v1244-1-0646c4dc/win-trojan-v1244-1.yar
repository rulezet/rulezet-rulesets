rule Win_Trojan_V1244_1
{
strings:
	$a0 = { 04bf00012e8b0ef202b4dd03f7cd21 }


condition:
	$a0
}