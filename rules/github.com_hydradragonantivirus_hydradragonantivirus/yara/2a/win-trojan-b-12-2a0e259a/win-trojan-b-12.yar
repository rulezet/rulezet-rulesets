rule Win_Trojan_B_12
{
strings:
	$a0 = { ba033b06ba017509a1bc033b06bc01742ec606080080b80103bb0002b90800ba8000cd13 }


condition:
	$a0
}