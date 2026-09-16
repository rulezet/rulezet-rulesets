rule Win_Downloader_Small_2056
{
strings:
	$a0 = { 1c687447703a2f17755364611b3a2e6d343930733d66 }


condition:
	$a0
}