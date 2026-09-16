rule Win_Downloader_Small_1967
{
strings:
	$a0 = { 6a006a006820161413686c1114136a00ff1518161413 }


condition:
	$a0
}