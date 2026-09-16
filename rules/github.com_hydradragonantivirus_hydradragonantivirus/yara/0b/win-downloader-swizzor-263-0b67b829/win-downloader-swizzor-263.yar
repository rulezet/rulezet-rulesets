rule Win_Downloader_Swizzor_263
{
strings:
	$a0 = { f6f6ccaab42a6719c42a814d57385282b67bc4a03bc7b6b6a72ab9eecb4c35843b99bfb9be52d51b3a17dc49d3d49259 }


condition:
	$a0
}