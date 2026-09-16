rule Win_Downloader_10105_1
{
strings:
	$a0 = { 558bec83ec00d9ee83ec1cd93424 }


condition:
	$a0
}