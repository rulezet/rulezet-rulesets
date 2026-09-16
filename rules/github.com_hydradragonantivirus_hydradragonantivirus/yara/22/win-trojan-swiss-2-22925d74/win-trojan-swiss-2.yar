rule Win_Trojan_Swiss_2
{
strings:
	$a0 = { 45c746000d00c704f3a4c64402c358bf }


condition:
	$a0
}