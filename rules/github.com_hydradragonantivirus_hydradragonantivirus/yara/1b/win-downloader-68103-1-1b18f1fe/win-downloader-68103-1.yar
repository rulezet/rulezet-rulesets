rule Win_Downloader_68103_1
{
strings:
	$a0 = { 6804bbda8a688f5908ae686e278edee825 }


condition:
	$a0
}