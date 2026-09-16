rule Win_Downloader_Small_1652
{
strings:
	$a0 = { 0fd5db0fdfe1d80424ba70e848000f6fe08d3f81e20000f0ffd9fbd82424 }


condition:
	$a0
}