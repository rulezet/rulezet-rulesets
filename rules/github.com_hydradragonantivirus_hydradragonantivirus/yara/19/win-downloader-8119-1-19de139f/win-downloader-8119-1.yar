rule Win_Downloader_8119_1
{
strings:
	$a0 = { 5568cb36400064ff30648920e8b9eeffffb870564000bae0364000e802f9ffff }


condition:
	$a0
}