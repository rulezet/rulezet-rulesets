rule Win_Downloader_Banload_1009
{
strings:
	$a0 = { 40008d45e4ba03000000e8b0f5ffffc3e922f0ffffebebe88ff4ffff000000ffffffff09000000696d6772742e636f6d000000ffffffff0d000000697865706c6f7265722e }


condition:
	$a0
}