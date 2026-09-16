rule Win_Trojan_Joker_2
{
strings:
	$a0 = { 21891ea9478c06ab471e0e1fba7a01b81b25 }


condition:
	$a0
}