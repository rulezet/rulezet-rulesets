rule Win_Downloader_Small_1780
{
strings:
	$a0 = { 7dae742065786b83b5f6706c6f720b11092e072842f4db7f687474703a2f2f77002e70757466cd08da2ff52e636fc46d6564 }


condition:
	$a0
}