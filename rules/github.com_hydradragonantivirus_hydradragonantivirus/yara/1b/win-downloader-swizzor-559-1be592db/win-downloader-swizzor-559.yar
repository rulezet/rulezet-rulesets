rule Win_Downloader_Swizzor_559
{
strings:
	$a0 = { 042bf2f8d9fdc154910f4b2ce001081ba518add62e930bd03c15a53a21af8efd03e9a2d7d3a5e31a42d5c3f866ea1964190ed497fd7f135fddfd3ff2b311cf2f3731c5adfbf426dbafea9f3f }


condition:
	$a0
}