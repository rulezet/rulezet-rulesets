rule Win_Trojan_Darkray_II_1
{
strings:
	$a0 = { e800005d81ed0701b4098d96be01cd218db6ca02bf0001fca5a5b42fcd212e899ed8022e8c86da02b41a8d96 }


condition:
	$a0
}