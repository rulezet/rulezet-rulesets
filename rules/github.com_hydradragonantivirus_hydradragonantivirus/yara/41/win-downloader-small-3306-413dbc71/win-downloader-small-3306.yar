rule Win_Downloader_Small_3306
{
strings:
	$a0 = { 5e517b3ab1d1a42559e3c7a792d44c046dc1c2d9a03888c1f641208bd3a973a26c0c4f9daccb623cd3b5f39e4603fa2abab1a00d15a673a7d9c9 }


condition:
	$a0
}