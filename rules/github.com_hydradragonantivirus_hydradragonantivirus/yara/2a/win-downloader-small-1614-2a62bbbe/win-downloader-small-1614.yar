rule Win_Downloader_Small_1614
{
strings:
	$a0 = { 506a006a006a046a006a006a0068843714136a00e8bafcffff6a00e8cbfcffff }


condition:
	$a0
}