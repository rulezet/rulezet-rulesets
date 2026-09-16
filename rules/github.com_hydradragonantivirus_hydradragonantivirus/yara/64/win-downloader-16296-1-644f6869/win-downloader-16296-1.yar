rule Win_Downloader_16296_1
{
strings:
	$a0 = { 68f87642006a00e88cfaffff8d8df8feffffba60774200b8a0774200e81ffcffff8b85f8feffffe8e0f4fdff84c00f85c10300008d85f8feffff8d95fdfeffffb9ff000000e8a2c5fdff }


condition:
	$a0
}