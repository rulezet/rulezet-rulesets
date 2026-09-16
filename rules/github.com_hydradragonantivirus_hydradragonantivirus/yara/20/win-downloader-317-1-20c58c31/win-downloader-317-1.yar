rule Win_Downloader_317_1
{
strings:
	$a0 = { 8d85b8fcffff8945d468d34ee4858d85bcfdffff6a02c745c43c000000897dccc745d0244040008945d8897ddc897de0c745c840000000e8fafdffff8d4dc451ffd085c0746b }


condition:
	$a0
}