rule Win_Trojan_Diamond_4
{
strings:
	$a0 = { d9be20008d7d19b8c501874464ab8c }


condition:
	$a0
}