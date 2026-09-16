rule Win_Trojan_Pox_8
{
strings:
	$a0 = { 010100558e00000000ffff00000000d6000000040000000103 }


condition:
	$a0
}