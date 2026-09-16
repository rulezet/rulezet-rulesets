rule Win_Trojan_Werehere_1
{
strings:
	$a0 = { 408b1e7a00ba0000b94403cd21b457 }


condition:
	$a0
}