rule Win_Trojan_HeyYou_1
{
strings:
	$a0 = { f9c707721c80fe02721780fa1972 }


condition:
	$a0
}