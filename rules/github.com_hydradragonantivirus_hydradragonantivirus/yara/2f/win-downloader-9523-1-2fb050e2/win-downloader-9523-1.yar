rule Win_Downloader_9523_1
{
strings:
	$a0 = { 38f00fbcfe80dc8380cad1eb01af4e0fc0e70fc1da0fa5c1470fa3fdff }


condition:
	$a0
}