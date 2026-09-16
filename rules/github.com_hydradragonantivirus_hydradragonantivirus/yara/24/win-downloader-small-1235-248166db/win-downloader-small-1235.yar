rule Win_Downloader_Small_1235
{
strings:
	$a0 = { 343546ac6871741c703a2f50773c2e4ac4bea98c3c657b }


condition:
	$a0
}