rule Win_Trojan_Kaabum_1
{
strings:
	$a0 = { b8004233c933d2e89c027303eb149083ef0389bc3b03b440b904008d943a03e88402b43ee8 }


condition:
	$a0
}