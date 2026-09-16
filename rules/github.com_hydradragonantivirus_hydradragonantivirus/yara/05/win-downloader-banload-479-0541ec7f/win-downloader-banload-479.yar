rule Win_Downloader_Banload_479
{
strings:
	$a0 = { 8b55ecb8a8a84000e88fb6ffffb8aca84000bae0804000e880b6ffff }


condition:
	$a0
}