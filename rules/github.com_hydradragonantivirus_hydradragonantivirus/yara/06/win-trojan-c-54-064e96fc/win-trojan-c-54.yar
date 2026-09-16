rule Win_Trojan_C_54
{
strings:
	$a0 = { 7c741cb80103600ee89bfefcb9c0018db73cfe8d7f3ef3a4c707eb3e61cd13071f619dea }


condition:
	$a0
}