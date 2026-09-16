rule Win_Downloader_Small_1473
{
strings:
	$a0 = { 7411703a2fc46e6f1c72646247732e63876ddf47656c4ededd61fe0f68312e6f78bc387da407e05501524c446f776e6c }


condition:
	$a0
}