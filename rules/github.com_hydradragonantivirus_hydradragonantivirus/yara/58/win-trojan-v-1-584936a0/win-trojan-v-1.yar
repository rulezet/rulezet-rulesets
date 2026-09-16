rule Win_Trojan_V_1
{
strings:
	$a0 = { 6f00b000e86100b440b91c00ba45020e1fcd21eb2db002e84e002d0300a343022d480239064602 }


condition:
	$a0
}