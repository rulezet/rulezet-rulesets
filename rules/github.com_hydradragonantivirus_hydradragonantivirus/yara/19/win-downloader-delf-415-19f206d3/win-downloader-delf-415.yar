rule Win_Downloader_Delf_415
{
strings:
	$a0 = { 5068b83515146a00e841ffffff6a05 }


condition:
	$a0
}