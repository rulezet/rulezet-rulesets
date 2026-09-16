rule Win_Downloader_Small_1751
{
strings:
	$a0 = { 6a006a05683c10400068101040006a00e81b000000 }


condition:
	$a0
}