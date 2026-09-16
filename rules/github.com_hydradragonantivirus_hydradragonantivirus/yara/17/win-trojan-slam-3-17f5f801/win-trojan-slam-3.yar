rule Win_Trojan_Slam_3
{
strings:
	$a0 = { 0166a00a013c00740c6630074302c781fbe4017ef4c3 }


condition:
	$a0
}