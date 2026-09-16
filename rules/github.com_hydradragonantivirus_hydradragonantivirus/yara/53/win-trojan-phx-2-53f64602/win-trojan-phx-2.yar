rule Win_Trojan_Phx_2
{
strings:
	$a0 = { b9380533d2e81700ba18002a164b058bcaba4b012bd1b440e80400e8bfffc39c2eff1e3805c3 }


condition:
	$a0
}