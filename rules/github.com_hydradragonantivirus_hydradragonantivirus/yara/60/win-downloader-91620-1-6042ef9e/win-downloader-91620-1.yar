rule Win_Downloader_91620_1
{
strings:
	$a0 = { 8bff558bec81ec680300000d3b0f0000818de8fcfffffa00000023c80bc18d9558feffff89e93351 }


condition:
	$a0
}