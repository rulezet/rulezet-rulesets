rule Win_Downloader_Small_5125
{
strings:
	$a0 = { 8ddd7e703a2f2f77002e675e62cf646765312ec26e85f6636f6d2fdc07166966276c7b6cfb6a736aa17820696d612b73 }


condition:
	$a0
}