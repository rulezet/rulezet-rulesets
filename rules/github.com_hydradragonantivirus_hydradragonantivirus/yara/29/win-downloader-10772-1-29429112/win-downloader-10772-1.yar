rule Win_Downloader_10772_1
{
strings:
	$a0 = { 87f690919187de87de5651595ebf121040009090 }


condition:
	$a0
}