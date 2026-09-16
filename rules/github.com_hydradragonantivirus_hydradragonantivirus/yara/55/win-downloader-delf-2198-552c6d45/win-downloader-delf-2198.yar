rule Win_Downloader_Delf_2198
{
strings:
	$a0 = { a59bb3c2224aa1d127abefe08b92b4757ceac7a2116836a18ff102dc3242dc1ec2c426cc5acd42735ef013de8208fcd7bbb8aa8fd3f5cefa39a1314b07c9c8c4c4746b879308ba3aeaa11c2975d15628 }


condition:
	$a0
}