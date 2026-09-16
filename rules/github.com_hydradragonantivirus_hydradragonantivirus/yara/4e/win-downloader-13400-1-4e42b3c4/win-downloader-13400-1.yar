rule Win_Downloader_13400_1
{
strings:
	$a0 = { 33d2a1fc5b4500e8407effffb874224500e86251fdff33d2b8??224500e852ffffffba[0-200]657865000000ffffffff??000000687474703a2f }


condition:
	$a0
}