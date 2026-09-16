rule Win_Downloader_Swizzor_310
{
strings:
	$a0 = { 061869da790c08e24383466689d8aefe800924b5555fff2a893a9589b2e59ce7d720c41ce9c3cc3c33eec3854b3c5729 }


condition:
	$a0
}