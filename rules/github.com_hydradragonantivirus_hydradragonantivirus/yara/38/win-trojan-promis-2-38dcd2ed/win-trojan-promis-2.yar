rule Win_Trojan_Promis_2
{
strings:
	$a0 = { 28a7f4138b3253f6ea0ae8a0f4f3b85ac81997cf2aa9df40ab339008bb129bb535f27f9b35cb819f }


condition:
	$a0
}