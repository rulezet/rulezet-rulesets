rule Win_Downloader_Small_1897
{
strings:
	$a0 = { a81340008bceff35c03a4000e8c8010000e8e1f8ffff }


condition:
	$a0
}