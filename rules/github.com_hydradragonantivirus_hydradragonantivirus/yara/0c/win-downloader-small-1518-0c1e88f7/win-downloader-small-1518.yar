rule Win_Downloader_Small_1518
{
strings:
	$a0 = { 01e54bfe4f6c6f616465725f6a6f62ffcc31ffffffff }


condition:
	$a0
}