rule Win_Trojan_SubSeven_11
{
strings:
	$a0 = { 189fdc10a536b5d62918d83ea85a636673b8ad20fc52cdd82949c110db31d0ada87b8c86d05a6b8461d9500a3999e0cea89cb6714660fe31c899211b8c71f294 }


condition:
	$a0
}