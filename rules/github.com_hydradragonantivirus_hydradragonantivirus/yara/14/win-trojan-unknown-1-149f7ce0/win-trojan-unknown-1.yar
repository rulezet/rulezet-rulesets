rule Win_Trojan_Unknown_1
{
strings:
	$a0 = { f63de326572c92936ea674289db631f9eb3a18f8a606dcf11ac0d5661ee0f2f8f45a0c52086ee492854536fd22 }


condition:
	$a0
}