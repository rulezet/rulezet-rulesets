rule Win_Trojan_Implant_1
{
strings:
	$a0 = { cd1281feadde750b81ffbeba7505eb00e9 }


condition:
	$a0
}