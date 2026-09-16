rule Win_Downloader_Banload_456
{
strings:
	$a0 = { 6a036864c94400e85096fbffbad0c94400b8f4c94400e845ffffff84c074146a036a006a006824ca44006a006a00e80d79fdff }


condition:
	$a0
}