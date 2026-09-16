rule Win_Downloader_5635_1
{
strings:
	$a0 = { 6a006a00682c43400068444340006a00e879fbffff6a006888434000e8a5faffff }


condition:
	$a0
}