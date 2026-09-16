rule Win_Downloader_Agent_35049
{
strings:
	$a0 = { 0441bbed8818f0a1ad2ac1dfda4576af8d5f6b8736b38afe722ee7794a4b5e17f7c27b092eb753cbcb4e530670898bbc3554 }


condition:
	$a0
}