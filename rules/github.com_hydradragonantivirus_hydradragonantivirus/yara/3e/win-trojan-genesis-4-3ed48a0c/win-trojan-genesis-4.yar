rule Win_Trojan_Genesis_4
{
strings:
	$a0 = { 03008986ef01b4408d960401b9ee00cd21b8004233c933d2cd21b904008d96ee01b440cd21 }


condition:
	$a0
}