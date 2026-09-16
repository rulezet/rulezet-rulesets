rule Win_Downloader_Small_1341
{
strings:
	$a0 = { 1c6412321419160c0286e10c04864422b9331a03cee870d7075868 }

	$a1 = { 66756c1162697ac46f6e }


condition:
	$a0 and $a1
}