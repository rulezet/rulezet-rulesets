rule Win_Downloader_Small_2033
{
strings:
	$a0 = { edd046ec6871741c703a2f7d6194792e63d56de864617274fe69f1d967b73a2ab1727563 }


condition:
	$a0
}