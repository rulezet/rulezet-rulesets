rule Win_Downloader_Small_1649
{
strings:
	$a0 = { da3c24bac08040000fdbdb89eddde081e20000f0ffd9ca8d0087f681c200920000da0c248cc987ffd80424 }


condition:
	$a0
}