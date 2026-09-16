rule Win_Trojan_Garsuni_2
{
strings:
	$a0 = { 596f75547562652d546f2d4d50332e657865 }

	$a1 = { 4e65747a53746172746572 }

	$a2 = { 4e65747a537566666978 }


condition:
	$a0 and $a1 and $a2
}