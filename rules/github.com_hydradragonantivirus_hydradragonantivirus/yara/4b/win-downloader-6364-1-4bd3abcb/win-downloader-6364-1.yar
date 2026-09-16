rule Win_Downloader_6364_1
{
strings:
	$a0 = { 87ff909090905790525a }


condition:
	$a0
}