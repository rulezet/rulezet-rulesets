rule Win_Downloader_Small_5135
{
strings:
	$a0 = { 687447703a2f1677021f2e6372f9f5fa68dc5cbaf9c21a6f6d2f8e11bffc1b616752e60cf3bd9f72652e8c663e4c7a1e3a }


condition:
	$a0
}