rule Win_Downloader_INService_30
{
strings:
	$a0 = { 73093130300d0a64096c69737431096c697374732e786d69 }


condition:
	$a0
}