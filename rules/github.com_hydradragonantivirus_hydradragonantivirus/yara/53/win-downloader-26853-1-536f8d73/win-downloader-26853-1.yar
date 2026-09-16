rule Win_Downloader_26853_1
{
strings:
	$a0 = { 9087db53535b905b90909292909087d290 }


condition:
	$a0
}