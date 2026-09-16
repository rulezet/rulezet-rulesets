rule Win_Downloader_Delf_831
{
strings:
	$a0 = { 558bec83c4f0b8dcd94000e8a073ffffba88da4000b8??da4000e8a9feffff84c0740c33d2b888da4000e80dfeffff }


condition:
	$a0
}