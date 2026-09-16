rule Win_Downloader_Small_1892
{
strings:
	$a0 = { 81ec0c02000066a140300010535556576689442410bf4430001083c9ff }


condition:
	$a0
}