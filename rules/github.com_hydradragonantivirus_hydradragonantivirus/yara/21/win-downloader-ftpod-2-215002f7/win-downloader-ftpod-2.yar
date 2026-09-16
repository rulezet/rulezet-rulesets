rule Win_Downloader_FTPod_2
{
strings:
	$a0 = { 6898604000e8fb07000083c40483c00150 }


condition:
	$a0
}