rule Win_Trojan_Gen_235
{
strings:
	$a0 = { 03018bfe5156b4ffac32c4c0c40302e1aae2f5bf00015e59f3a4be000156c3 }


condition:
	$a0
}