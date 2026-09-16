rule Win_Trojan_Vgen_130
{
strings:
	$a0 = { 8ec0fcb90001f3a5ea61002000e88601b404cd1a81fa02057578b80300cd10b401b520cd10b8 }


condition:
	$a0
}