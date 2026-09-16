rule Win_Trojan_Sistor_4
{
strings:
	$a0 = { 062e8b84de008cc203c20510002e8984de00b430 }


condition:
	$a0
}