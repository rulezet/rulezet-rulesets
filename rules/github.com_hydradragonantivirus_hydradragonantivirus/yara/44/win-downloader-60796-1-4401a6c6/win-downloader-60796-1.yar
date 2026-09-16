rule Win_Downloader_60796_1
{
strings:
	$a0 = { 558becb878e4701bbb116babc750e800000000582da81a0000b96d1a0000ba211b0000be0010 }


condition:
	$a0
}