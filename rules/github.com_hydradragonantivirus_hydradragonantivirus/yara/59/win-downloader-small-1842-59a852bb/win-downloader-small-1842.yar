rule Win_Downloader_Small_1842
{
strings:
	$a0 = { 0fd5d187dbbaffffffff89db87ed8d008d1281c200a20000d9e0d9fa }


condition:
	$a0
}