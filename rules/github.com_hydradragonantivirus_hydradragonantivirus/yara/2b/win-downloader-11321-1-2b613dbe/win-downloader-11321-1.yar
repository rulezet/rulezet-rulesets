rule Win_Downloader_11321_1
{
strings:
	$a0 = { 5068103940006a00e8a5feffff6a0a8d45e4e8e3feffff8d45e4ba54394000e83af8ffff8b45e4e802f9ffff50e888feffff }


condition:
	$a0
}