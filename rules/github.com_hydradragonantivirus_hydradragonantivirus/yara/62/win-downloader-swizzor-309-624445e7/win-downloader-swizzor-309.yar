rule Win_Downloader_Swizzor_309
{
strings:
	$a0 = { b0274dafa0607b0f4a9e569c2f6e41da425691afa61aa987e9fc2cd661e518040155c9c59bc0ed77f566b124b488f518 }


condition:
	$a0
}