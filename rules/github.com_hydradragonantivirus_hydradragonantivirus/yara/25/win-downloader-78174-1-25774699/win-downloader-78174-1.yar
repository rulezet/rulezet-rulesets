rule Win_Downloader_78174_1
{
strings:
	$a0 = { 0ae880c91cd3f380f4f31bf902f232c6f6dc80d9cdbb75e980f0d2c4e9a1020000ec4069 }


condition:
	$a0
}