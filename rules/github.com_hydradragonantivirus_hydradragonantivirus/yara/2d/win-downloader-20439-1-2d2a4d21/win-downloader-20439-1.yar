rule Win_Downloader_20439_1
{
strings:
	$a0 = { 5152905a595153905b5987db87db87db }


condition:
	$a0
}