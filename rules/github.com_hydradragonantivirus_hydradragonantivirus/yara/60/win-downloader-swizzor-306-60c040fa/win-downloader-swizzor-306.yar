rule Win_Downloader_Swizzor_306
{
strings:
	$a0 = { bd9643050ce3054926a861fd5b5143dfac632e8f0d21b5e96be3551e81da7a573e3503f53c6e83826161c84ad953a93b }


condition:
	$a0
}