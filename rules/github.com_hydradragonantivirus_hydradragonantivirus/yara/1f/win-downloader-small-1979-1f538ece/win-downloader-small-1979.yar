rule Win_Downloader_Small_1979
{
strings:
	$a0 = { 8945e88d450868b8124000508d45e450c645fc03e828110000 }


condition:
	$a0
}