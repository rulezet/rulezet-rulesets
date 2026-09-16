rule Win_Downloader_134622_1
{
strings:
	$a0 = { 8a510c8a1832da8818408d143081fa00040000 }


condition:
	$a0
}