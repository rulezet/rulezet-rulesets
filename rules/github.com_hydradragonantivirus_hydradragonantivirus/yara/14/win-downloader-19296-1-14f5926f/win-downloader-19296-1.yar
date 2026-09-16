rule Win_Downloader_19296_1
{
strings:
	$a0 = { 8bd0b818af400059e856aaffffe8d1a4ffffb818af4000e867aaffffe8c2a4ffff6a006a006a00a164b04000e8e2b8ffff5068648340006a00e869c5ffff }


condition:
	$a0
}