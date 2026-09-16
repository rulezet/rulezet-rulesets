rule Win_Downloader_10363_1
{
strings:
	$a0 = { 9c60e8000000005d83ed078d8d9efeffff8039010f8442020000 }


condition:
	$a0
}