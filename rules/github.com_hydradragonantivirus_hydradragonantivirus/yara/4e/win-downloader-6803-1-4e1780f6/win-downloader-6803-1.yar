rule Win_Downloader_6803_1
{
strings:
	$a0 = { 8b55ecb8f4804000e8c2fdffff84c0742c8d45e0e8e2feffff }


condition:
	$a0
}