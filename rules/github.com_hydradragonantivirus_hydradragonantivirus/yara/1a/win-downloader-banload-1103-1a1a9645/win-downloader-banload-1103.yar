rule Win_Downloader_Banload_1103
{
strings:
	$a0 = { b8be8673a5b55a864840aa8d0d59ddedc6d016e904a77d50c614affcc3b4cc8d01c45abb5eab12750185ddbd21b993f25a9e8833542b8dd3c56a6c9d11e37f33f80f424fd5d6fc }


condition:
	$a0
}