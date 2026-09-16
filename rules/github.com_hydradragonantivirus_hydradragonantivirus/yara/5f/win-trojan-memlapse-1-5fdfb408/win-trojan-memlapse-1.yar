rule Win_Trojan_Memlapse_1
{
strings:
	$a0 = { 1e02890e2002b440b904008d962602cd21b8024233c933d2cd21b440b930018d960001cd21b8 }


condition:
	$a0
}