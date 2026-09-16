rule Win_Trojan_Kazyinvoker_1
{
strings:
	$a0 = { 4b0061007a00790049006e0076006f006b0065007200 }


condition:
	$a0
}