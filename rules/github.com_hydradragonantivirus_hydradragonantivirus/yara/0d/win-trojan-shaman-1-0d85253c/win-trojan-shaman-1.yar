rule Win_Trojan_Shaman_1
{
strings:
	$a0 = { c501b440ba0001b9fb00cd2172185ab4408b0ccd21 }


condition:
	$a0
}