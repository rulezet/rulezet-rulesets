rule Win_Trojan_Ash_10
{
strings:
	$a0 = { 40b904008d96fa01cd21b8024233c933d2cd21b4408b0e3b02ba0401cd21b801438b8e2e02cd21 }


condition:
	$a0
}