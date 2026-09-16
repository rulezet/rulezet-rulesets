rule Win_Downloader_Delf_108
{
strings:
	$a0 = { 697374696e61385f77686974652f736869742e747874000000ffffffff0100000000 }


condition:
	$a0
}