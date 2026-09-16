rule Win_Downloader_Swizzor_280
{
strings:
	$a0 = { 58e5f3301b26250146b75c28e9e334fe3a9514c436275f972c04608bfbe4511ea0e8b3017a07ff37a8737d11348a62e4 }


condition:
	$a0
}