rule Win_Downloader_Small_3388
{
strings:
	$a0 = { f7a0219fac1283b1c16b8ade96e3f3f13f40213116cf1fc6f91b1ce9038d6a3ca1991a25f27eb6a56b0d327051ede2d02cec9ef821276639216b345b268f873beb441c6e8f }


condition:
	$a0
}