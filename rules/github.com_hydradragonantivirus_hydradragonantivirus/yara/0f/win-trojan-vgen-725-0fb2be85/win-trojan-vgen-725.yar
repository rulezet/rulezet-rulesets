rule Win_Trojan_VGEN_725
{
strings:
	$a0 = { b81335cd21891ebe7d8c06c07db81325ba517dcd21bf0a00b80102bb41010e07b90100ba8000cd13730733c0cd13 }


condition:
	$a0
}