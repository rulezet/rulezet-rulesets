rule Win_Downloader_1329_1
{
strings:
	$a0 = { ba0132ecba81c2ffff54458d8a38f000ff8d894414ff0052525131c050505454e812000000 }


condition:
	$a0
}