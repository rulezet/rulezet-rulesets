rule Win_Downloader_5850_1
{
strings:
	$a0 = { 8b2dac40151368c8000000ffd56818421513ff15d0401513 }


condition:
	$a0
}