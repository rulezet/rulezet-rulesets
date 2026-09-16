rule Win_Downloader_Delf_1013
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffff33d2b8807f4000e8d0feffffbaec7f4000b824804000e821feffff84c0740c33d2 }


condition:
	$a0
}