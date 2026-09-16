rule Win_Trojan_BlackJack_4
{
strings:
	$a0 = { 1d023df0ff7764f8b8023d8bd3cd218b }


condition:
	$a0
}