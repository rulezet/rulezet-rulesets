rule Win_Downloader_294_2
{
strings:
	$a0 = { fb9271e2b1d52f9e5c66f02af808d8a8f8e3188c5c5f502a78c22e3cdc07f0aaf800d6c948492e9e5cc8902af6c2d6a6f6e930e489230edd8e4478bc0ae8159ca6c45fb1bc810c5cac449591d2bb }


condition:
	$a0
}