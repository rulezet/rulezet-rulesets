rule Win_Downloader_5639_1
{
strings:
	$a0 = { 558bec6a00535633c05568a85f400064ff30648920bac05f4000b802000080e8a8ecffff }


condition:
	$a0
}