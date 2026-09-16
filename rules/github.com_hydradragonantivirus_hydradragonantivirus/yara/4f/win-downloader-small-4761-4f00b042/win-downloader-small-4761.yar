rule Win_Downloader_Small_4761
{
strings:
	$a0 = { f3a4bec41040008d85ecfcffff56506801000080e862eaffff }


condition:
	$a0
}