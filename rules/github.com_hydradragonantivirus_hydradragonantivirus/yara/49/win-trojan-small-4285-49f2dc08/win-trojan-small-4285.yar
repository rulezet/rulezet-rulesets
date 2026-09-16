rule Win_Trojan_Small_4285
{
strings:
	$a0 = { e9??000000[0-255]e80000000059[0-255]9160505b31c9 }


condition:
	$a0
}