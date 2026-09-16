rule Win_Trojan_Korea_3
{
strings:
	$a0 = { c08ed88ed0bcf0fffbbb13048b074848 }


condition:
	$a0
}