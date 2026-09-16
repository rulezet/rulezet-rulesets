rule Win_Downloader_FTPod_1
{
strings:
	$a0 = { 83c4048985f4feffff68ac604000e86c0a000083c40483c00150e8e8090000 }


condition:
	$a0
}