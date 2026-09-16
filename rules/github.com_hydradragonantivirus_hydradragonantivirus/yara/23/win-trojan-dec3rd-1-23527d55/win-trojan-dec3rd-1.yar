rule Win_Trojan_Dec3rd_1
{
strings:
	$a0 = { e800005bb9240580770e????43[0-2]e2f6 }


condition:
	$a0
}