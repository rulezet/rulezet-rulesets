rule Win_Downloader_6794_1
{
strings:
	$a0 = { 60e8000000005b5383c40409db61eb5ccc??feffff9090606a }


condition:
	$a0
}