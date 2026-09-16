rule Win_Downloader_26844_1
{
strings:
	$a0 = { 905250585a87ca9087ca909087f287f2929287f187f1909090 }


condition:
	$a0
}