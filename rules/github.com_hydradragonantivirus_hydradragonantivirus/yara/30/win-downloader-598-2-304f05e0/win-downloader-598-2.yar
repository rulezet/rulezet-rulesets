rule Win_Downloader_598_2
{
strings:
	$a0 = { 33d2a1d0fb4400e8407effff33d2b8f4c94400e85cffffffba14ca4400b850ca4400e8adfeffff84c0740c33d2b814ca4400e83dffffff }


condition:
	$a0
}