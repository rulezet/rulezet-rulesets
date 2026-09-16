rule Win_Downloader_3084_1
{
strings:
	$a0 = { 8b55ecb89c804000e8bdfdffff84c0742c8d45e0e8ddfeffffff75e0687c8040006888804000 }


condition:
	$a0
}