rule Win_Downloader_6813_1
{
strings:
	$a0 = { 0fc90fc1f118d40fb7d964 }


condition:
	$a0
}