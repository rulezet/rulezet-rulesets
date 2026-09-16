rule Win_Downloader_Dadobra_254
{
strings:
	$a0 = { 6efbffebe55b8be55dc30000ffffffff0b0000005c53797374656d2e65786500687474703a2f2f777777 }

	$a1 = { 2e62722f00558bec6a00538bd833 }


condition:
	$a0 and $a1
}