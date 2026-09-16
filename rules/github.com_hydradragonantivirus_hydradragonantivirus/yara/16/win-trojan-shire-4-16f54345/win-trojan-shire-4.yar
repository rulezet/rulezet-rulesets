rule Win_Trojan_Shire_4
{
strings:
	$a0 = { 1200b8034e8d95430088854200cd217318ba8000b41ab9 }


condition:
	$a0
}