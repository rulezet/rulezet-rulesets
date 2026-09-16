rule Win_Downloader_Small_1868
{
strings:
	$a0 = { 6a006a00a11420400050a110204000506a006834124000 }


condition:
	$a0
}