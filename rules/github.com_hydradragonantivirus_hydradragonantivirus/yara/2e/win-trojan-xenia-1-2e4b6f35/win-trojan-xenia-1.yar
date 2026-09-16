rule Win_Trojan_Xenia_1
{
strings:
	$a0 = { 03018bfe5156b4ffac32c4c0c40302e1aae2f5 }


condition:
	$a0
}