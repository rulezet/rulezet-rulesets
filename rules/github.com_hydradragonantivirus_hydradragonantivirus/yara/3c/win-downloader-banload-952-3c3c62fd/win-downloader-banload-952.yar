rule Win_Downloader_Banload_952
{
strings:
	$a0 = { c300ffffffff09000000696d6772742e736372000000ffffffff22000000687474703a2f2f }


condition:
	$a0
}