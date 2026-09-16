rule Win_Trojan_Garsuni_4
{
strings:
	$a0 = { 53637265656e2d5265636f7264696e672d53756974652e657865 }

	$a1 = { 4e65747a53746172746572 }

	$a2 = { 4e65747a537566666978 }


condition:
	$a0 and $a1 and $a2
}