rule Win_Downloader_Swizzor_270
{
strings:
	$a0 = { 2983bd3f022a043f4fa09e6f7cc473d7cde707dcd6cf9b06369bf277f43daa14aea9483b1c62ce7fbaa7445ebf59ba26 }


condition:
	$a0
}