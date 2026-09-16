rule Win_Downloader_Small_1727
{
strings:
	$a0 = { 68cb204000684d204000680b204000e8ceffffff83c40c83ec208d0424506a286affe821040000 }


condition:
	$a0
}