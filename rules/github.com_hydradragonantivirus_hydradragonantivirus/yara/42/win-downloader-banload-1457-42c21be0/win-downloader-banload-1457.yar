rule Win_Downloader_Banload_1457
{
strings:
	$a0 = { ba58c94400b874c94400e851ffffff84c07414 }


condition:
	$a0
}