rule Win_Downloader_Agent_31783
{
strings:
	$a0 = { 206d6f726f6e73298f42fe7f00737663686f73742e657865005379ff9dfbff73 }


condition:
	$a0
}