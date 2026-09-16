rule Win_Downloader_Upatre_3347
{
strings:
	$a0 = { 74656d706f730053696d4865690047726561742057616c6c00 }


condition:
	$a0
}