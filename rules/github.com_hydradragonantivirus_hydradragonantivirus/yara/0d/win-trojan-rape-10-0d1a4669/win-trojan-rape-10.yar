rule Win_Trojan_Rape_10
{
strings:
	$a0 = { e800005e81ee03008beefc5006561eb42acd213c007503eb0490e9c901b401b92020cd10b40233d2cd1033c0cd10b40eb049cd10b40eb074cd10b40eb027cd10b40eb0 }


condition:
	$a0
}