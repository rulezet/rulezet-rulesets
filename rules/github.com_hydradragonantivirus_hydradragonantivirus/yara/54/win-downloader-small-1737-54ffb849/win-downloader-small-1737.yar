rule Win_Downloader_Small_1737
{
strings:
	$a0 = { 0f6fc00fefd8e800000000 }


condition:
	$a0
}