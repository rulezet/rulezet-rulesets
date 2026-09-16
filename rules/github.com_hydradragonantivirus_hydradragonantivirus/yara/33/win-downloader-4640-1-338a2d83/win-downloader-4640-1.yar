rule Win_Downloader_4640_1
{
strings:
	$a0 = { 808c51687474703a2f2f736c696c2e72752f323339 }


condition:
	$a0
}