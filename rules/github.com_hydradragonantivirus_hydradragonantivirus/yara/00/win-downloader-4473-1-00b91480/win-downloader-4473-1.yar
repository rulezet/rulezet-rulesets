rule Win_Downloader_4473_1
{
strings:
	$a0 = { c4ec33c08945ecb8847f4000e88fc5ffff33c05568??80400064ff306489206a0368??804000e8a1c6ffff }


condition:
	$a0
}