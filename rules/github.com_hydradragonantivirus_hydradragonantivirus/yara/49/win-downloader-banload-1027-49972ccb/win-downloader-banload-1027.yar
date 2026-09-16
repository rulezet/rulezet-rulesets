rule Win_Downloader_Banload_1027
{
strings:
	$a0 = { 506a25b1e362c1b5524c06487ed77ccb0caa4b624265618bb9669e95dd6d25f19712cfdce1a093b973ae4eba432b70c1e5832564 }


condition:
	$a0
}