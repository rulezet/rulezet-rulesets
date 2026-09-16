rule Win_Downloader_94237_1
{
strings:
	$a0 = { 6d617269612e657865 }

	$a1 = { 616d61735c63727272732e6578 }


condition:
	$a0 and $a1
}