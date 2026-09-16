rule Win_Downloader_106377_1
{
strings:
	$a0 = { 83ec085355565733ed8d1c1b8b3d043040005555555555ffd7555555558bf055 }


condition:
	$a0
}