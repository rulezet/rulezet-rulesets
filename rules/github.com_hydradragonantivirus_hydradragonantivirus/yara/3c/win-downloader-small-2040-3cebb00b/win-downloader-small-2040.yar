rule Win_Downloader_Small_2040
{
strings:
	$a0 = { 8b4de88d45e050e8c2feffff8945e88d450868b8124000508d45e450c645fc03e847100000 }


condition:
	$a0
}