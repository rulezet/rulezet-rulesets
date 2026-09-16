rule Win_Downloader_63728_1
{
strings:
	$a0 = { 31c0e801000000c389ff89e583ec148d5dec6a006a006a006a006a006a006a00ff }


condition:
	$a0
}