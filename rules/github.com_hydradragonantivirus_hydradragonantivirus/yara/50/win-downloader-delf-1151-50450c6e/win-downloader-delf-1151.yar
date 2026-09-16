rule Win_Downloader_Delf_1151
{
strings:
	$a0 = { 646cdd61ca71d71afd3464e6d8eb60db9d0dd20f1f8bcd840b72af1a545328e1289f036f9da3b47ad66aaec0e88490b1cc67c4f6a374f8897afa5ee7cff2eb5d5c82054b487f93c1ee6cd4d471947b8763 }


condition:
	$a0
}