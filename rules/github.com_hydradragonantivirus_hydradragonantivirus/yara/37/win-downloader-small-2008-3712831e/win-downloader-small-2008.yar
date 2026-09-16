rule Win_Downloader_Small_2008
{
strings:
	$a0 = { 6a006a016803204000ff35b00e4500e87c02000083f8ff7428 }


condition:
	$a0
}