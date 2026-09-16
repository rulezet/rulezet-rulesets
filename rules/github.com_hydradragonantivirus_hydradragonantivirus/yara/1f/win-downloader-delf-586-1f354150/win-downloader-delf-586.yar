rule Win_Downloader_Delf_586
{
strings:
	$a0 = { 508d55dca1a0404000e8f1fdffff8b45dce8bdf6ffff506a00e881fdffff }


condition:
	$a0
}