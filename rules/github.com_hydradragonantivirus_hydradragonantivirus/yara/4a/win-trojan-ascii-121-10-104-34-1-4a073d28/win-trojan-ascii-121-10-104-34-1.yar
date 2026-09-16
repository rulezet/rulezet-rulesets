rule Win_Trojan_Ascii_121_10_104_34_1
{
strings:
	$a0 = { 3132312e31302e3130342e3334 }


condition:
	$a0
}