rule Win_Downloader_Small_1841
{
strings:
	$a0 = { 558bec83ec4456ff15341040008bf08a063c2275143c2274088a46014684c075f4 }


condition:
	$a0
}