rule Win_Trojan_Zany_6
{
strings:
	$a0 = { 03be6c0003f5bfc80003fdb90300f3a4b44eba700003d5b92000cd217236ba9e00b80143b91000cd21b8023dcd }


condition:
	$a0
}