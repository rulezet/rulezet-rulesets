rule Win_Downloader_11268_1
{
strings:
	$a0 = { 6a018d4db4ba88364100b8d0374100e871e0ffff8b45b4508d45b0e83de2ffff8d45b0ba30374100e8fc15ffff8b55b033c958e855e4ffff84c00f8402010000eb07 }


condition:
	$a0
}