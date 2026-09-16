rule Win_Downloader_4038_1
{
strings:
	$a0 = { 558bec6830404000b970464000e81c0e00005dc3 }


condition:
	$a0
}