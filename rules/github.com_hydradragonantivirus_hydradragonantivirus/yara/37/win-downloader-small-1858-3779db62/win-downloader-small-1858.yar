rule Win_Downloader_Small_1858
{
strings:
	$a0 = { 508d45fc33ff5057683f000f005757576870144000680200008033f6897dfcff150c104000 }


condition:
	$a0
}