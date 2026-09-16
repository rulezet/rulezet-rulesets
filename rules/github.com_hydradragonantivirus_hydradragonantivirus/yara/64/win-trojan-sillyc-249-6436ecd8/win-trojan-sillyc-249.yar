rule Win_Trojan_SillyC_249
{
strings:
	$a0 = { e800005b81eb21018beb8db64201568b960b02b964008bfe3afdfcad33c2ab3afce2f8 }


condition:
	$a0
}