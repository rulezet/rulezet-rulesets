rule Win_Trojan_Eumel_23
{
strings:
	$a0 = { 01babcfcb98901cd21b80042e84600b43080c410b903008d963c02cd21b801575a59cd21 }


condition:
	$a0
}