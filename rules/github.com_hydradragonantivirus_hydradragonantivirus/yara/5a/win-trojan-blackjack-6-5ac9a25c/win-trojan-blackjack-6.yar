rule Win_Trojan_BlackJack_6
{
strings:
	$a0 = { 218bda8b073d909074503d4d5a744b }


condition:
	$a0
}