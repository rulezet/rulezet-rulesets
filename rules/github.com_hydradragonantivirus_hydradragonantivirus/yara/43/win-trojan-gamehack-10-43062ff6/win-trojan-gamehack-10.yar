rule Win_Trojan_Gamehack_10
{
strings:
	$a0 = { 57696e41637469766174652822434142414c2229 }


condition:
	$a0
}