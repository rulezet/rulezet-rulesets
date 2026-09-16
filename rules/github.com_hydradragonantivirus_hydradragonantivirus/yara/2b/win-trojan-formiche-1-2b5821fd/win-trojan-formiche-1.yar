rule Win_Trojan_Formiche_1
{
strings:
	$a0 = { b74c01bcd21746313431244c75f8 }


condition:
	$a0
}