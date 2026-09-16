rule Win_Downloader_1382_1
{
strings:
	$a0 = { 65652d706f72fc6344ff6e2d6d6f76696573596164762f6c2e74f68de842 }


condition:
	$a0
}