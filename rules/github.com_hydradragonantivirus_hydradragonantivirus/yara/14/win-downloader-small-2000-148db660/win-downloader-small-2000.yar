rule Win_Downloader_Small_2000
{
strings:
	$a0 = { 787878787878787878787878787878787878005f2e45784500c410 }


condition:
	$a0
}