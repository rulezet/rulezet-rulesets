rule Win_Downloader_Swizzor_290
{
strings:
	$a0 = { d7561a6d9bcca0e24b9ce053ba1a60e0f8eb0865f363f18f77da28b020994de699308bcfda1f29e02f62e21603c7d55b }


condition:
	$a0
}