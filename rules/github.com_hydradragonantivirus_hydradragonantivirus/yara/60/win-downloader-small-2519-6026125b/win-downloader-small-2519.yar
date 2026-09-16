rule Win_Downloader_Small_2519
{
strings:
	$a0 = { 80633a5c05626c616e6b200e558bec7281301804125356571c33f6b91b0114b8c08dbd30 }


condition:
	$a0
}