rule Win_Trojan_Astra_6
{
strings:
	$a0 = { 0200b4409c2eff1ecd0033c98b16160081c28d1eb800429c2eff1ecd00b4409c2eff1ecd }


condition:
	$a0
}