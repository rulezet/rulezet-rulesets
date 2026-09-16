rule Win_Trojan_Small_4232
{
strings:
	$a0 = { 53562bf35e575783 }


condition:
	$a0
}