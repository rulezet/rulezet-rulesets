rule Win_Trojan_Ascii_142_0_128_29_1
{
strings:
	$a0 = { 3134322e302e3132382e3239 }


condition:
	$a0
}