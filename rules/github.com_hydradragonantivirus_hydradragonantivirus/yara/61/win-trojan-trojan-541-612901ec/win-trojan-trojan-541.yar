rule Win_Trojan_Trojan_541
{
strings:
	$a0 = { 8a2630a1??????0083c601803e00742483e9ff83ea0175e8[24]c9c208000bc28bf7ebd6 }


condition:
	$a0
}