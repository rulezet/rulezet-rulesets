rule Win_Downloader_51_2
{
strings:
	$a0 = { 6874361413a1a4401413506a00e898feffff6a056874361413e8c4fdffff }


condition:
	$a0
}