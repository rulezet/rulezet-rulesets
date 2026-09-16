rule Win_Trojan_TDSS_69
{
strings:
	$a0 = { 565733f6568b04a5 }

	$a1 = { 4d6a4d6a376a2c5050 }


condition:
	$a0 and $a1
}