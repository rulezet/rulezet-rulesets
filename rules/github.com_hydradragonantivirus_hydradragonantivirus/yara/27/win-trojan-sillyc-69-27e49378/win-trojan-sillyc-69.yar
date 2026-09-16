rule Win_Trojan_SillyC_69
{
strings:
	$a0 = { 8d960001cd21b8004233c933d2cd21b440b904008d }


condition:
	$a0
}