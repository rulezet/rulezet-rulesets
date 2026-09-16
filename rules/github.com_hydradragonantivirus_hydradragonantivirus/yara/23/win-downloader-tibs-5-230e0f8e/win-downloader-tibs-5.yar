rule Win_Downloader_Tibs_5
{
strings:
	$a0 = { d9c9baffffffff89c9da3424 }


condition:
	$a0
}