rule Win_Downloader_Small_2603
{
strings:
	$a0 = { 68000200008d85f8feffff506a00ff153020400085c074166a018d8df8feffff68??20400051e8020009 }


condition:
	$a0
}