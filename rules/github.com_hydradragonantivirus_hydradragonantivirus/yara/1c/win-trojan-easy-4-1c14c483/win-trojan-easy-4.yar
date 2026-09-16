rule Win_Trojan_Easy_4
{
strings:
	$a0 = { 010100558e00000000ffff00000000d7010000050000000903 }


condition:
	$a0
}