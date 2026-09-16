rule Win_Trojan_Gen_222
{
strings:
	$a0 = { f1f30b0d6ce6faffd5007f077c4f3d3912764ad2fc9ff00fcff4bdd27803fde819e8e1fb8c }


condition:
	$a0
}