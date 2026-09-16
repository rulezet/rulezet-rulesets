rule Win_Trojan_Serg_2
{
strings:
	$a0 = { b8addecd2181fa9619[0-5]b80049cd21[0-5]b80048bbffffcd21 }


condition:
	$a0
}