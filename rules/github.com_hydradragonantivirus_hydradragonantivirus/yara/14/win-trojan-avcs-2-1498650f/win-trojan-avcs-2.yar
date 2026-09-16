rule Win_Trojan_Avcs_2
{
strings:
	$a0 = { e800005b81eb????8beb8db6????568b96????b97500[0-2]fc8bfead33c2d1caab3ad0e2f6 }


condition:
	$a0
}