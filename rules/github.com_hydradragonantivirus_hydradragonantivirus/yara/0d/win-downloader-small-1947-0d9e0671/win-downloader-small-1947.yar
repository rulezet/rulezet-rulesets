rule Win_Downloader_Small_1947
{
strings:
	$a0 = { 687447703a2f1edfbe7a076962612e63866d18efe92d438677c76f7e5b6746fb687d266f5f947dcc312e8466a748cf43 }


condition:
	$a0
}