rule Win_Downloader_Small_1146
{
strings:
	$a0 = { 74006c6f76652e65786500000000687474703a2f2f6d61782d7374 }


condition:
	$a0
}