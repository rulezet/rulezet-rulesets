rule Win_Downloader_Banload_412
{
strings:
	$a0 = { ffffff0b000000433a5c497361732e73637200ffffffff2c000000687474703a2f2f }


condition:
	$a0
}