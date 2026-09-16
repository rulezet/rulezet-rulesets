rule Win_Downloader_284_1
{
strings:
	$a0 = { 00b4152d3ad2568ddd8bc792e04abee8a699dbfa7819f10f8acf759e0cfb648f3e739aa4d475be05e242bf0ad7e06fcb68a1c502925704ea233bf4a97350a4e6d54b7152dda33d66435d054d2fa0 }


condition:
	$a0
}