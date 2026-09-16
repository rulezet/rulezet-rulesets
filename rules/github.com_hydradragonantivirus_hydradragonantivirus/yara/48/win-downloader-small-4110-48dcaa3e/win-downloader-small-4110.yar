rule Win_Downloader_Small_4110
{
strings:
	$a0 = { cd2a85d27405e841000000cd1eb83726f60f01450083c504 }


condition:
	$a0
}