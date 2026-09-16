rule Win_Downloader_63727_1
{
strings:
	$a0 = { 5083e00053575256510f848b01000085c37052 }

	$a1 = { c96d7117656d7120656d711c656d71776c6d7117 }


condition:
	$a0 and $a1
}