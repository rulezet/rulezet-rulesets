rule Win_Downloader_60795_1
{
strings:
	$a0 = { f2c1e80bf8730161f2054ae8d386e802000000d0e859f283f053f223c1eb0210d703c98d3550 }


condition:
	$a0
}