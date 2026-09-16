rule Win_Trojan_Companion_16
{
strings:
	$a0 = { 01b90000b43ccd21723a93b92301ba0001b440cd21b43ecd21ba5301b90300b80143cd21eb07 }


condition:
	$a0
}