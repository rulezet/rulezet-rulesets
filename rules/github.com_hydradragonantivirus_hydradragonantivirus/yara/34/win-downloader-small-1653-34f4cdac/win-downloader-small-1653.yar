rule Win_Downloader_Small_1653
{
strings:
	$a0 = { d9fe0fdbcce8000000008d09d9c85a }


condition:
	$a0
}