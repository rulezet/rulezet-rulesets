rule Win_Downloader_245_1
{
strings:
	$a0 = { 558bec6830404000b9f0454000e81c0e00005dc3 }


condition:
	$a0
}