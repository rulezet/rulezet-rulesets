rule Win_Downloader_Small_1961
{
strings:
	$a0 = { ba282140008d4ddcffd68b75088d4dc4518d55d88b068d4ddc525156ff90f8060000 }


condition:
	$a0
}