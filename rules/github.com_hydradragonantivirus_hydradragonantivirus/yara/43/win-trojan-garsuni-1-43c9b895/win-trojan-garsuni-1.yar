rule Win_Trojan_Garsuni_1
{
strings:
	$a0 = { 57696e576f72642e657865 }

	$a1 = { 4e65747a53746172746572 }

	$a2 = { 4e65747a537566666978 }


condition:
	$a0 and $a1 and $a2
}