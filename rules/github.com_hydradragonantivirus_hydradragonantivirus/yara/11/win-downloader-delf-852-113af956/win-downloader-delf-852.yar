rule Win_Downloader_Delf_852
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffff33d2b8807f4000e8d0feffffbaa87f4000b8cc7f4000e821feffff84c0740c33d2b8a87f4000e8b1feffff }


condition:
	$a0
}