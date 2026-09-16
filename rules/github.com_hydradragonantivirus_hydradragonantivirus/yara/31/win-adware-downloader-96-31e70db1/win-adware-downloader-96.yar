rule Win_Adware_Downloader_96
{
strings:
	$a0 = { 6e75525c6e6f6973726556746e65727275435c73776f646e695700006f736f6674 }

	$a1 = { 772e66656e6f6d656e2d67616d65 }


condition:
	$a0 and $a1
}