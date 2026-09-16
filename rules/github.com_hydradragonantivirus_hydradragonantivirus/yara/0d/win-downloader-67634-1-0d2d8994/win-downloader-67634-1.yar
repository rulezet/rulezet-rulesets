rule Win_Downloader_67634_1
{
strings:
	$a0 = { e8280000000604004c0000006300000d00c2000062 }

	$a1 = { 4c33280a085c543d57996ef2 }


condition:
	$a0 and $a1
}