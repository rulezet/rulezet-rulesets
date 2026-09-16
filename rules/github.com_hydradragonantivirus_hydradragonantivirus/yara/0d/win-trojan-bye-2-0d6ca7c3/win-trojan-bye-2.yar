rule Win_Trojan_Bye_2
{
strings:
	$a0 = { c08ed0bb007c89dcfb505350b0108ed8ff8f13878b871387b1062d1f00d3e050500753b80202b9 }


condition:
	$a0
}