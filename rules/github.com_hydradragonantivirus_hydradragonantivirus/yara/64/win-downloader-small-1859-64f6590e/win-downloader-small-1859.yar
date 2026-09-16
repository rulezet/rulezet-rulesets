rule Win_Downloader_Small_1859
{
strings:
	$a0 = { 70663473fdbdb6fb732e6578650b61760d0a175f5f31d81fbbac021c6f0f7574706f7374226cc88f3d007a6c14636c69656e }


condition:
	$a0
}