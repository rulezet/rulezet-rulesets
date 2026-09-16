rule Win_Downloader_Small_361
{
strings:
	$a0 = { 386b2e636f6d2f69046f2f6d736f70742e646c6ceaff490b580a2b69656665616473dbdf76b16c2f0a74320532696e73 }


condition:
	$a0
}