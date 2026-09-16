rule Win_Downloader_Delph_3
{
strings:
	$a0 = { 5864720c1bd4a7fbbf039c00ba5c7379736b65792e646c6c43f67fe17f7474703a2f2f78706555616d2e }


condition:
	$a0
}