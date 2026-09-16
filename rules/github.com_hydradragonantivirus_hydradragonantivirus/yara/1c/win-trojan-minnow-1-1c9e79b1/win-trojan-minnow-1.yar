rule Win_Trojan_Minnow_1
{
strings:
	$a0 = { e800005e8ec0bf1c0226803de8742db9 }


condition:
	$a0
}