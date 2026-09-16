rule Win_Trojan_Gen_44
{
strings:
	$a0 = { ecbe3c01bf0000b91000fcf2a4e9 }


condition:
	$a0
}