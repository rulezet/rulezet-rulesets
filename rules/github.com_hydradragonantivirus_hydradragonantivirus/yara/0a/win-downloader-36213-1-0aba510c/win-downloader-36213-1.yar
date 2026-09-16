rule Win_Downloader_36213_1
{
strings:
	$a0 = { b8f4214500e807fdffff33c05a595964891068972045006a00b8e02145008d55ece8c35afbff8b45ece88322fbff50e8893ffbff }


condition:
	$a0
}