rule Win_Downloader_Swizzor_318
{
strings:
	$a0 = { ede1ef72d4a0fb86f5a9f2b148c3fb66ba5cee7489428fc00b48d7e464972c0ea29468880fd4e659c26ca909fe56d8f0 }


condition:
	$a0
}