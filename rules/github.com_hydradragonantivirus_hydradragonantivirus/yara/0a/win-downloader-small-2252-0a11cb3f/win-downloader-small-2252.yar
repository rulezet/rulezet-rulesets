rule Win_Downloader_Small_2252
{
strings:
	$a0 = { e8e0fdffff68381b14136aff6a00e89afbffff688c311413e8c8fbffff687c31141368383114136a006a006a046a006a006a0068481b14136a00e88efbffff }


condition:
	$a0
}