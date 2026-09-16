rule Win_Downloader_Small_1391
{
strings:
	$a0 = { 8a656badada3bcddfdfc670ab715770efdea32e3ae65b6cf444d0a085463eed65a2161e240af5cf76c86b7d6238908ff25c4d4059cbf0882cc0062697a2ffbe59bff74652f006361742e00703a2f2f }


condition:
	$a0
}