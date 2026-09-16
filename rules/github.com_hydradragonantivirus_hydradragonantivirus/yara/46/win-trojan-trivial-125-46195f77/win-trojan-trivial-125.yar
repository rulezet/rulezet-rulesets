rule Win_Trojan_Trivial_125
{
strings:
	$a0 = { ba1800b44ecd21ba9e00b43ccd21ba0000b740b11c93cd21 }


condition:
	$a0
}