rule Win_Downloader_8324_1
{
strings:
	$a0 = { 35342e39322e38322f63702f736372697074732f757064617465 }


condition:
	$a0
}