rule Win_Downloader_Delf_2073
{
strings:
	$a0 = { 6a006a00682c35400068443540006a00e84dffffff }


condition:
	$a0
}