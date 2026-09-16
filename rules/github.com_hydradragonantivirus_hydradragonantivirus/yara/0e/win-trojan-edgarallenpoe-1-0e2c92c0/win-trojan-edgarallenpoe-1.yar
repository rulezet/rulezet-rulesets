rule Win_Trojan_EdgarAllenPoe_1
{
strings:
	$a0 = { e90300??????bf1301bb16002e8107????43434f75f6 }


condition:
	$a0
}