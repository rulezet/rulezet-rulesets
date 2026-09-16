rule Win_Trojan_King_1
{
strings:
	$a0 = { 33c98a860501f6d088860501454181f9f4017403e9ebff2be9e900fe }


condition:
	$a0
}