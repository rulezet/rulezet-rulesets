rule Win_Downloader_Swizzor_311
{
strings:
	$a0 = { f200abc421bab34fcdbd141b3c16b1af902d72366d23dce936b45247c3312a52f9fb353c29e85164e27be42caa7d6691 }


condition:
	$a0
}