rule Win_Downloader_429_1
{
strings:
	$a0 = { 508d45e88b15a0404000e850f8ffff8b45e85ae893feffff84c0741b6a006a0068e4374000a1a44040005068e83740006a00e86cfdffff }


condition:
	$a0
}