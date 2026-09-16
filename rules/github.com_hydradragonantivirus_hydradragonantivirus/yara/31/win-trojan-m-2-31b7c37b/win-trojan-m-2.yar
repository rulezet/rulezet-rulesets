rule Win_Trojan_M_2
{
strings:
	$a0 = { 0e080083f9077507ba8000cd13eb2b8b }


condition:
	$a0
}