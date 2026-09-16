rule Win_Trojan_Tie_2
{
strings:
	$a0 = { 029033d2b4409c2eff1e1c00b442b00033c933d29c2eff1e1c00b90300ba2900b4409c2eff1e }


condition:
	$a0
}