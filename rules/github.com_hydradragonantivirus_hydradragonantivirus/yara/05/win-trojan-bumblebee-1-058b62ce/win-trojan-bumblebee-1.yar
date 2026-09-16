rule Win_Trojan_Bumblebee_1
{
strings:
	$a0 = { 0200558e00000000ffff00000000790500000b0000007408 }


condition:
	$a0
}