rule Win_Downloader_1400_1
{
strings:
	$a0 = { b9cbdcb8f381c13565880c518d99b016440081eb3412440051b9f846410089e2 }


condition:
	$a0
}