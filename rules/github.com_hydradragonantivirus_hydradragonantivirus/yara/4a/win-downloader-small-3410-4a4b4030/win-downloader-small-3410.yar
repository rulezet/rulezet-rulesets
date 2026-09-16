rule Win_Downloader_Small_3410
{
strings:
	$a0 = { f9c0633a5c74730a6b6d677252a32c7132087397027c6179 }


condition:
	$a0
}