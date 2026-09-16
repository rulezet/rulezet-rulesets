rule Win_Downloader_6815_1
{
strings:
	$a0 = { 558bec83c4f0b8??7f4000e8??c3ffffb8??804000e8??fdffffe8??b4ffff00ffffffff??000000687474703a }


condition:
	$a0
}