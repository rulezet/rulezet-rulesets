rule Win_Downloader_Small_2723
{
strings:
	$a0 = { c77508b3c2c992048f3a2f458aa314361f006871741c703a2f5d62f90e696c67 }


condition:
	$a0
}