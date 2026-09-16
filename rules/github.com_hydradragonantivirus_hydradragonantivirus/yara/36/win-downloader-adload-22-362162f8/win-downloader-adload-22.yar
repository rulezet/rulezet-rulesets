rule Win_Downloader_Adload_22
{
strings:
	$a0 = { ff5004c745fc01000000c745fc02000000c78538feffff741a4000c78530feffff080000008d9530feffff8d4da0ff15a8104000 }


condition:
	$a0
}