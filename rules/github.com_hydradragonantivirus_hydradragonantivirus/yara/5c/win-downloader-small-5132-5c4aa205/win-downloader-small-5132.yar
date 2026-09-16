rule Win_Downloader_Small_5132
{
strings:
	$a0 = { 6d2f3fc2fe2f63732e6578653c633a5c6366696707b6ca66240063780b641f6b0062667563 }


condition:
	$a0
}