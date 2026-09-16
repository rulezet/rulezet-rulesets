rule Win_Trojan_Small_4275
{
strings:
	$a0 = { 5805bc090000505f[0-255]c1eb1069db00000100 }


condition:
	$a0
}