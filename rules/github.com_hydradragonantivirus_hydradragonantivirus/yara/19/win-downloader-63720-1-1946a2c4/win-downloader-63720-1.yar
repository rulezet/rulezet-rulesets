rule Win_Downloader_63720_1
{
strings:
	$a0 = { 89e8e85200000031c00036ed1c07a865000000d1004600fb9b2f00980000080fa1dc376d0f0d00 }


condition:
	$a0
}