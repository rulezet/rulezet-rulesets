rule Win_Trojan_SoFar_2
{
strings:
	$a0 = { 535157561e065281c210008edabfad0390a0200330852f014feb0079f7 }


condition:
	$a0
}