rule Win_Downloader_Small_1807
{
strings:
	$a0 = { 23703a2f8b773f022eb9640e6e3231f4813f74ecf41878515f11b2206e669f3d3d0f3a5c625e }


condition:
	$a0
}