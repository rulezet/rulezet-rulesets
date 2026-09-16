rule Win_Downloader_Banload_1109
{
strings:
	$a0 = { ffffffff17000000633a5c57696e646f77735c72656773657276652e65786500ffffffff??000000687474703a2f2f7777772e }


condition:
	$a0
}