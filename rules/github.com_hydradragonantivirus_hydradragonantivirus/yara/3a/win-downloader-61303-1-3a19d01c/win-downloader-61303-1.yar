rule Win_Downloader_61303_1
{
strings:
	$a0 = { 558bec6aff68f0b3420068c08e420064a100000000506489250000000083ec685356 }

	$a1 = { 0a5850565353 }


condition:
	$a0 and $a1
}