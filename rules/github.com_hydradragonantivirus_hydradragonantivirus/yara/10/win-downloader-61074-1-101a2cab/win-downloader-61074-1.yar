rule Win_Downloader_61074_1
{
strings:
	$a0 = { 6895ef712a29f681f6ab59c6b856b957c4ace7f7d1516834[0-65]4f39d174292b3774f768633d }


condition:
	$a0
}