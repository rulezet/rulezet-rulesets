rule Win_Trojan_Peed_71
{
strings:
	$a0 = { ba8140420087ca6a006a006a006a006a }


condition:
	$a0
}