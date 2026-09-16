rule Win_Downloader_Agent_37032
{
strings:
	$a0 = { 33948df8fbffff8b4d08034df88811 }


condition:
	$a0
}