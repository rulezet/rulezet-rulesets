rule Win_Trojan_Bashar_1
{
strings:
	$a0 = { be13058bfe81c763029bdbe39b2edd059b2edd159b }


condition:
	$a0
}