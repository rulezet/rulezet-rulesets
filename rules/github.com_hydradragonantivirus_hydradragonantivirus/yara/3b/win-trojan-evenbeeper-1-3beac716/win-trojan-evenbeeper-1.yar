rule Win_Trojan_EvenBeeper_1
{
strings:
	$a0 = { 201e57bf48001e57b8881350bf8a201e579ac70861009a46026100bf08201e579a5d08 }


condition:
	$a0
}