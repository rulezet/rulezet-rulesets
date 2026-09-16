rule Win_Trojan_Hybryd_1
{
strings:
	$a0 = { 7ccd13beb07de81600be6b7cb90800b6388ac6e670ace67149fec675f4ebfeac0ac07409b40e }


condition:
	$a0
}