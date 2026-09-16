rule Win_Trojan_Bancos_661
{
strings:
	$a0 = { 0eaeae79cbdb1e6656c8061cbfe5519c561c4c573f75382a2fa3ec818a8795031ed4c5942742c7ed80c69506091c097e2cdbb40c761d5fabbcebee31ed05229ea2c8432a }


condition:
	$a0
}