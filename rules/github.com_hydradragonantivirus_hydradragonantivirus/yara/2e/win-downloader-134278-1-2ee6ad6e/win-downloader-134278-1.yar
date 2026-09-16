rule Win_Downloader_134278_1
{
strings:
	$a0 = { ff750883e103f3aae860fcffff8024330083c4108d45f4c745f404010000508d85ecfdffff }


condition:
	$a0
}