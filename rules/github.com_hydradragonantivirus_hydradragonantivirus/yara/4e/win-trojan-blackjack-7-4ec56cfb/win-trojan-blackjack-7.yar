rule Win_Trojan_BlackJack_7
{
strings:
	$a0 = { b43cb900008b16fe00f8cd218bd8b440 }


condition:
	$a0
}