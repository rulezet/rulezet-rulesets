rule Win_Trojan_B_96
{
strings:
	$a0 = { 02f8c3f9c3c70631010102eb06c70631010103e887ffa13101e85503c3 }


condition:
	$a0
}