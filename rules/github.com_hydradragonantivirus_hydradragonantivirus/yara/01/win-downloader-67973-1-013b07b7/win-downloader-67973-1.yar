rule Win_Downloader_67973_1
{
strings:
	$a0 = { 558bec6aff682045410068d455400064a1000000005064 }


condition:
	$a0
}