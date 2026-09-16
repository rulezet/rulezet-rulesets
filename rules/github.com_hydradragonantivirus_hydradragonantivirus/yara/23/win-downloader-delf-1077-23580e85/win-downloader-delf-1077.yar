rule Win_Downloader_Delf_1077
{
strings:
	$a0 = { 558bec83c4f0b8d87e4000e8ecc4ffffba847f4000b8b47f4000e8cdfeffff }


condition:
	$a0
}