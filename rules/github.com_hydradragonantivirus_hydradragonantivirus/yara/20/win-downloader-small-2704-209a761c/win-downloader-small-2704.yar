rule Win_Downloader_Small_2704
{
strings:
	$a0 = { 572a6a01db0392524c446f77fa6c5caf1e5425c6ed874663687488703a2f }


condition:
	$a0
}