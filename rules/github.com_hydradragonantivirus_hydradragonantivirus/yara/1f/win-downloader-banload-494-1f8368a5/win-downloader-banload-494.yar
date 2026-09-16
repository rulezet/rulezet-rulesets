rule Win_Downloader_Banload_494
{
strings:
	$a0 = { e8d1f8ffff8b55fcb830384000e8dcfeffff }


condition:
	$a0
}