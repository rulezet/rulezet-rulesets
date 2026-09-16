rule Win_Downloader_Small_5143
{
strings:
	$a0 = { b92e0100008a1d2f114000be0010400089f7ac08c0740630d8aa4975f5680010400059ffd1 }


condition:
	$a0
}