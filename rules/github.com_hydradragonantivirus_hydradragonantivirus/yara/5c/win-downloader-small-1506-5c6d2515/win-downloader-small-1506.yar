rule Win_Downloader_Small_1506
{
strings:
	$a0 = { a300154000685c10400053e88a000000 }


condition:
	$a0
}