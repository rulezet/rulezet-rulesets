rule Win_Downloader_2292_1
{
strings:
	$a0 = { 636f6d2e62722f0000ffffffff0e000000433a5c737663686f73742e6578650000ffffffff2200000068747470 }


condition:
	$a0
}