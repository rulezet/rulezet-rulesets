rule Win_Trojan_Hermetica_1
{
strings:
	$a0 = { e800005d81ed0400060e1fb80335cd21899ed7038c86d903e87702b81935cd218bd38cc08ed8b80325cd210e0e1f07 }


condition:
	$a0
}