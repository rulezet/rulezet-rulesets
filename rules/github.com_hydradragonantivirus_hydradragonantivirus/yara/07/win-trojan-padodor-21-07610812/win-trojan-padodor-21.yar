rule Win_Trojan_Padodor_21
{
strings:
	$a0 = { e8170200008b7dfc8d7c382809fb8dbde8feffff8d3590300010b904000000f3a5 }


condition:
	$a0
}