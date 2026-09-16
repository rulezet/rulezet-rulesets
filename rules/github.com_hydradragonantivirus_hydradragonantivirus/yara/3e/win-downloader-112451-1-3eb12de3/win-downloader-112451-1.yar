rule Win_Downloader_112451_1
{
strings:
	$a0 = { 558bec6aff68a820400068e015400064a100000000506489250000000083ec68 }

	$a1 = { 2f6c6f676f2e747874 }


condition:
	$a0 and $a1
}