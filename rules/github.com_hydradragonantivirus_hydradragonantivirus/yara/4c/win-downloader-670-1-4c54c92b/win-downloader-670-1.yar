rule Win_Downloader_670_1
{
strings:
	$a0 = { 31c981c1cb????f381c13565cc0c518d99e8f20fff81c33412f00051b9df????0089e26a006a006a0052ff1159b8ffdfeebe29018d490439d97ee0c3 }


condition:
	$a0
}