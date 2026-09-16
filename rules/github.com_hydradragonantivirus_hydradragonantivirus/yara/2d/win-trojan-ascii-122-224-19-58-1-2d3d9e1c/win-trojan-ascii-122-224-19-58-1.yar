rule Win_Trojan_Ascii_122_224_19_58_1
{
strings:
	$a0 = { 3132322e3232342e31392e3538 }


condition:
	$a0
}