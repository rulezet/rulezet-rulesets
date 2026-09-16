rule Win_Trojan_Philis_182
{
strings:
	$a0 = { 525a515183c4040f02cb5083c4045933c3 }


condition:
	$a0
}