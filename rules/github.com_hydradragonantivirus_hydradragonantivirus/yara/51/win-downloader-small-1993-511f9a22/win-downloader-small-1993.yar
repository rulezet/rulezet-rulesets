rule Win_Downloader_Small_1993
{
strings:
	$a0 = { 558bec6a006a00682c214000e8befbffff83c40c6a006a00685c214000e8adfbffff }


condition:
	$a0
}