rule Win_Downloader_1297_1
{
strings:
	$a0 = { 680004f00f6822560400e802000000ffe05589e5ba01????f681c2ffff870952e829000000e82a000000 }


condition:
	$a0
}