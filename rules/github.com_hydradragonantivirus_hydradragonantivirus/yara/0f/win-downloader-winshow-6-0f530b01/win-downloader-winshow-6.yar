rule Win_Downloader_Winshow_6
{
strings:
	$a0 = { ba034aac263bddd9b3cd1a0e3b7ff03a07083b18364d67369c3603f4cab836ff07ebce1fccafbab3687474703a2f2f303038b2f2ffff6b2e636f6d2f69636f6f2f6d736f }


condition:
	$a0
}