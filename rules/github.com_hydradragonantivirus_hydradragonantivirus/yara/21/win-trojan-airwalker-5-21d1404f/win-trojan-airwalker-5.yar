rule Win_Trojan_Airwalker_5
{
strings:
	$a0 = { 8d76098bfeb9ac00adcc7304abe2f9c3356c4e73f7 }


condition:
	$a0
}