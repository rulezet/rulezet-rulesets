rule Win_Downloader_131446_1
{
strings:
	$a0 = { 687474703a2f2f6d79736974652e636f6d2f7669722e657865 }


condition:
	$a0
}