rule Win_Trojan_Corrupted_61
{
strings:
	$a0 = { 4d5990000300000004000000feff0003b8 }


condition:
	$a0
}