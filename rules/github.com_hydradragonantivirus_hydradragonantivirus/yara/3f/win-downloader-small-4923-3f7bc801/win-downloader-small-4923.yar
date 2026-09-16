rule Win_Downloader_Small_4923
{
strings:
	$a0 = { 558bec6a0168a4204000e856fcffff83c4086a106a0068cc2040006a00ff15441040006a00ff1528104000 }


condition:
	$a0
}