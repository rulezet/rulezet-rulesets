rule Win_Downloader_Small_2019
{
strings:
	$a0 = { 528d55f88b0703c3538bd88b47f80345f452ff77fc5350ff75fce8c8020000 }


condition:
	$a0
}