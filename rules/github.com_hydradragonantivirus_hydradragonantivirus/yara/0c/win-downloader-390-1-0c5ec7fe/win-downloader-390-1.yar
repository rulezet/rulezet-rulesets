rule Win_Downloader_390_1
{
strings:
	$a0 = { e800000000b8f56755006a006a00ff1085c07535b8d8675500ff1085c0742a }


condition:
	$a0
}