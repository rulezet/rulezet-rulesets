rule Win_Trojan_Sistor_5
{
strings:
	$a0 = { ee06002e8b84e9008cc203c20510002e8984e900b430 }


condition:
	$a0
}