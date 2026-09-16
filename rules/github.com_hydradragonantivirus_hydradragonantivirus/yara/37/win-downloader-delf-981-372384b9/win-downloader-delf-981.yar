rule Win_Downloader_Delf_981
{
strings:
	$a0 = { 6a056a006a00688c7f40006a006a00e874feffffb8c07f4000e80ad5ffff84c0752bbac07f4000b8e07f4000e897feffff84c0740c6a006800804000e8f7c5ffff }


condition:
	$a0
}