rule Win_Downloader_6356_1
{
strings:
	$a0 = { 25881b6666392e74d1cca82d00752e651804006c7474703a2f2f63627366588037 }


condition:
	$a0
}