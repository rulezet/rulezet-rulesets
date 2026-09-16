rule Win_Downloader_Swizzor_550
{
strings:
	$a0 = { 70e921c99f47032282e508ffd881b36e1664f2dd100ea340f45a85da5f36b1c7ecb6cb91e94f1f3334c1386085811418 }


condition:
	$a0
}