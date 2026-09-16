rule Win_Downloader_63718_1
{
strings:
	$a0 = { 68343ad21c8134240b044b41893c24e92d0500008bf683c4048bbc2424010000e8a0fdffff894c }


condition:
	$a0
}