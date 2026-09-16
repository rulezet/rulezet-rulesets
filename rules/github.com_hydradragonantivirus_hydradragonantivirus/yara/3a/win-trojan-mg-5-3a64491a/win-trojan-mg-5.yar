rule Win_Trojan_MG_5
{
strings:
	$a0 = { 7213b8004231d28bcacdffb440b90300ba }


condition:
	$a0
}