rule Win_Trojan_Peed_137
{
strings:
	$a0 = { 81c244a21a01920f859e00000083c404bf00 }


condition:
	$a0
}