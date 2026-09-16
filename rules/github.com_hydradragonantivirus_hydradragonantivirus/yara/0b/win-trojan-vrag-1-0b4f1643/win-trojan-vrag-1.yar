rule Win_Trojan_Vrag_1
{
strings:
	$a0 = { 3e52010f74228cc88ed8b44033d2b98c01cd2133c933d28bc0b80042cd21b440ba5301b90400 }


condition:
	$a0
}