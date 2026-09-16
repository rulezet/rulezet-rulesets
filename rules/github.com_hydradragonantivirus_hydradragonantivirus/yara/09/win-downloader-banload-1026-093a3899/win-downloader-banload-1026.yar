rule Win_Downloader_Banload_1026
{
strings:
	$a0 = { 9ae3b1a033664eda04dd53c78e6b409a890b63b2a6e4906d255277972ed400e140718d30b3e3f1708d0de51f14902771fc121614 }


condition:
	$a0
}