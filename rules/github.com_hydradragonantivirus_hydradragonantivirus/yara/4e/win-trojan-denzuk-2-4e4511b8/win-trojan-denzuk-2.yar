rule Win_Trojan_DenZuk_2
{
strings:
	$a0 = { 1931d2b94029bb007eb80902cd1372ef }


condition:
	$a0
}