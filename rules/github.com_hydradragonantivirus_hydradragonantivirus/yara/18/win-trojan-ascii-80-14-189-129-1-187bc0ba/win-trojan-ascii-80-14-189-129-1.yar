rule Win_Trojan_Ascii_80_14_189_129_1
{
strings:
	$a0 = { 38302e31342e3138392e313239 }


condition:
	$a0
}