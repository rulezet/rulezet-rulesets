rule Win_Trojan_Anarkia_2
{
strings:
	$a0 = { cd2180fce1731380fc03072e8e1645002e8b2643002e }


condition:
	$a0
}