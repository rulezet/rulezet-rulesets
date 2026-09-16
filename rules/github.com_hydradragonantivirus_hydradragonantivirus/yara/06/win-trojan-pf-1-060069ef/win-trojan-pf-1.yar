rule Win_Trojan_PF_1
{
strings:
	$a0 = { 4c00a37c01a14e00a37e01b85046cd133d4650744dc7064c00e5008c0e4e00fb2e803e62008074 }


condition:
	$a0
}