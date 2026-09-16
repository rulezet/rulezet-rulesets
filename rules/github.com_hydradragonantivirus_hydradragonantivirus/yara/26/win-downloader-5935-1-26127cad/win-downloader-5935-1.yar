rule Win_Downloader_5935_1
{
strings:
	$a0 = { 2d3c0f960fa4c1ccc7c6cd5cafb60fbcc8c7c66d7c4f }


condition:
	$a0
}