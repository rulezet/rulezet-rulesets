rule Win_Downloader_5250_1
{
strings:
	$a0 = { 648920b8a8a74000ba7c864000e83cb7ffffa1a8a74000e852b9ffff }


condition:
	$a0
}