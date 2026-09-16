rule Win_Downloader_Swizzor_314
{
strings:
	$a0 = { c480dc467a5862f1af09a86dbf090ecc73c5e9e160876554728147837ab07a789302d677b9d6f14b12c90a16a8a5f71d }


condition:
	$a0
}