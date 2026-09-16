rule Win_Trojan_Dnepr_1
{
strings:
	$a0 = { 0131d2b440cdffb8004231c9cdffb440ba4f00b10389 }


condition:
	$a0
}