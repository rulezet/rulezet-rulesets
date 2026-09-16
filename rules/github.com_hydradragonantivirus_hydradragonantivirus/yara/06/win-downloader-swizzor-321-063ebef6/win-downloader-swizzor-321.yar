rule Win_Downloader_Swizzor_321
{
strings:
	$a0 = { ca58e11035446c7ebe931eeec39b7de9e176e12433854fb5c5b9e6fa921f3d19c69946ec5ca001648bb1ac6c78dcdc29 }


condition:
	$a0
}