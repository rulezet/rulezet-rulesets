rule Win_Downloader_Delf_901
{
strings:
	$a0 = { 6a006a00a18020141350a17c201413506a00e8cdfdffff6a00a18020141350e8f8fcffff }


condition:
	$a0
}