rule Win_Trojan_Grog_WildCards_1
{
strings:
	$a0 = { b8003d8d963f04cd219353b82012cd2feb12470772076f07 }


condition:
	$a0
}