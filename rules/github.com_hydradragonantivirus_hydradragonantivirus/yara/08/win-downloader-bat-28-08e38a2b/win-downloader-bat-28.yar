rule Win_Downloader_Bat_28
{
strings:
	$a0 = { 6f70656e20[0-45]62696e[0-10]47455420[0-50]2e657865[0-5]71756974 }


condition:
	$a0
}