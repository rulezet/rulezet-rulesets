rule Win_Downloader_Small_1375
{
strings:
	$a0 = { 7472617977386e64005553455233322e38444cf0a50155e06674703a712f }


condition:
	$a0
}