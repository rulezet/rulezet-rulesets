rule Win_Downloader_Small_1282
{
strings:
	$a0 = { 558bec83ec305657be342040008d7df4a5a566a56a08be10204000598d7dd0f3a5a433f6 }


condition:
	$a0
}