rule Win_Trojan_CrazyEddie_1
{
strings:
	$a0 = { 53b80301cf813c4d5a7404813c5a4d }


condition:
	$a0
}