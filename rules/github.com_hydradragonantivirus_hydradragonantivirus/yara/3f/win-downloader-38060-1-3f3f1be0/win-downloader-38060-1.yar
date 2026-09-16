rule Win_Downloader_38060_1
{
strings:
	$a0 = { b8c4954500e86d16fbff84c00f8404020000b90c954500b201a1b88f4200e8c424fdff8bd88d45fcba68944500e849d0faff8d45f8baf0954500e83cd0faff }


condition:
	$a0
}