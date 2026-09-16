rule Win_Trojan_Dre_1
{
strings:
	$a0 = { 860501f6d088860501454181f9b6027403e9ebff }


condition:
	$a0
}