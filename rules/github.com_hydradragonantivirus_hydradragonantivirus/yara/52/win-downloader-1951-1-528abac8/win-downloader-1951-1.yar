rule Win_Downloader_1951_1
{
strings:
	$a0 = { 3c41535820 }

	$a1 = { 2f636f646563732e65786522 }


condition:
	$a0 and $a1
}