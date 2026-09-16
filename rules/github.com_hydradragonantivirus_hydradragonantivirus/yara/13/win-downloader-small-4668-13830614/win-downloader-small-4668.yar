rule Win_Downloader_Small_4668
{
strings:
	$a0 = { 656e6c6f6f6b2e696e666f2f7365617263682e7068703f71713d4f72616c2b536578266964 }


condition:
	$a0
}