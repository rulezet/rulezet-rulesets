rule Win_Downloader_Small_2110
{
strings:
	$a0 = { e88d20000056576850500010e8aa1b0000 }


condition:
	$a0
}