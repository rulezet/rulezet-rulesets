rule Win_Trojan_VGEN_121
{
strings:
	$a0 = { d289db89f683ce0083e5ff89c089db89ff83e5ff83cb0089f689db89ff83c20083ce0089c089db89c983cb0083c200 }


condition:
	$a0
}