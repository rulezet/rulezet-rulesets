rule Win_Trojan_BlackJack_3
{
strings:
	$a0 = { 023df0ff775ef8b8023d8bd3cd218b }


condition:
	$a0
}