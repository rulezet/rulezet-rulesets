rule Win_Downloader_1594_1
{
strings:
	$a0 = { 558bec83c4f0b818364000e83cfdffff33c05568????400064ff30648920e8b9eeffff6a0168????4000e8d1fd }


condition:
	$a0
}