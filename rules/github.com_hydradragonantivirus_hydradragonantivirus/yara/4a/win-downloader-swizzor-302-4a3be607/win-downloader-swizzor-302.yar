rule Win_Downloader_Swizzor_302
{
strings:
	$a0 = { 1449eab33f105681b8a4f0067f438c13f57d3da85292c82dcae8a98edefeb6743647c32f1d06f4cfd79fea1a6ca55842 }


condition:
	$a0
}