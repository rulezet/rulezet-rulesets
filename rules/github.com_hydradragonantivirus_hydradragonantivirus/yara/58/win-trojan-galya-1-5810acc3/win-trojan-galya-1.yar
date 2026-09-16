rule Win_Trojan_Galya_1
{
strings:
	$a0 = { 8cd80539018ed8fcbf0001b4eecd2180fcef750ebec302b904008bdf58f3a41f53c3b44abb3200cd21b42acd2180 }


condition:
	$a0
}