rule Win_Trojan_Mini_HHHH_1
{
strings:
	$a0 = { 81ef0b015733f681c7fc01b99900f3a4bf00015e5681c6e301b90300f3a45a5281c2e901b92000b44ecd217310e990 }


condition:
	$a0
}