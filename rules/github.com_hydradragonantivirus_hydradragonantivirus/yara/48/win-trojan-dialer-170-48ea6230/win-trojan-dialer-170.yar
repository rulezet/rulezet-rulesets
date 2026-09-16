rule Win_Trojan_Dialer_170
{
strings:
	$a0 = { 3c2f68616cd8dd28db476430006f7065b37ffbfedd5c032557494e444952250f771f3836636f6d2efddd85e773797344 }


condition:
	$a0
}