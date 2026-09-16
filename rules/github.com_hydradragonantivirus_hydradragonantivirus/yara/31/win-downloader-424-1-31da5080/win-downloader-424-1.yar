rule Win_Downloader_424_1
{
strings:
	$a0 = { e8baf3ffffe81de7ffffe860dfffffba884814138bc3e8a4f3ffffe807e7ffffe84adfffff33d28bc3e891f3ffffe8f4e6ffffe837dfffff8bc3e888e4ffffe82bdfffff6a0068a4481413e8e7f7ffff }


condition:
	$a0
}