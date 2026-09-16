rule Win_Downloader_Small_1862
{
strings:
	$a0 = { 8bca8d94248401000083e103f3a4bf2060400083c9fff2aef7d1 }


condition:
	$a0
}