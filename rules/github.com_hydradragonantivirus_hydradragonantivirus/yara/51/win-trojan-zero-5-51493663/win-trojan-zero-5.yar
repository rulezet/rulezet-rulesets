rule Win_Trojan_Zero_5
{
strings:
	$a0 = { 0226803de8742db99f0183ee03f3a4 }


condition:
	$a0
}