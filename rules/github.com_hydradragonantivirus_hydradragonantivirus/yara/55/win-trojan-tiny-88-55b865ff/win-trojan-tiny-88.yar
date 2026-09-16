rule Win_Trojan_Tiny_88
{
strings:
	$a0 = { 40cd218b1644008b0e4600b80042cd21ba4800b94000b440cd2133c9ba0800b80142cd21ba9c00 }


condition:
	$a0
}