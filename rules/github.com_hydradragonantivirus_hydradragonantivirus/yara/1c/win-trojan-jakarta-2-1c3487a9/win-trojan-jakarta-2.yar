rule Win_Trojan_Jakarta_2
{
strings:
	$a0 = { 02b44099e8650073063bc17302eb1433c9b8004299e85400b440b91000ba4102e84900be3902 }


condition:
	$a0
}