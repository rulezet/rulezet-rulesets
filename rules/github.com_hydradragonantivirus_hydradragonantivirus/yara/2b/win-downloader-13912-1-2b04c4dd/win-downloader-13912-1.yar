rule Win_Downloader_13912_1
{
strings:
	$a0 = { 8d55ecb844201413e807fcffff8b55ecb89c461413e8baf4ffffe871fcffffe828fdffff33c05a59596489106835201413 }


condition:
	$a0
}