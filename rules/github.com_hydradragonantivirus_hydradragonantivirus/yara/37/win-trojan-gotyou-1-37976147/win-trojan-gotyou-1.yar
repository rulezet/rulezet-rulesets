rule Win_Trojan_GotYou_1
{
strings:
	$a0 = { 4000c5aafff0413a0034122a2e2a0047204f5420594f }


condition:
	$a0
}