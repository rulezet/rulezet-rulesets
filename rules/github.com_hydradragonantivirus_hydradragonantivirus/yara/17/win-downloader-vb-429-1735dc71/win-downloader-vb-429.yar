rule Win_Downloader_VB_429
{
strings:
	$a0 = { 4d0bba27dd302521dec1bf042128f80fea72abb123b1cbdc9d9d84d38f2f8997f11fccedd2897d861ba90c508dd6a8f413d00087af19fb2520275d59924bfb89 }


condition:
	$a0
}