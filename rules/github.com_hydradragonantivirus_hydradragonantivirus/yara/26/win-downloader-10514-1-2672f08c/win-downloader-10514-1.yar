rule Win_Downloader_10514_1
{
strings:
	$a0 = { 87ff9057905f52565e90 }


condition:
	$a0
}