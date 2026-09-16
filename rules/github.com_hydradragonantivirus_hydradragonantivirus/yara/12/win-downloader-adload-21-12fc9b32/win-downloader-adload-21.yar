rule Win_Downloader_Adload_21
{
strings:
	$a0 = { c745fc01000000c745fc02000000c78568feffff641a4000c78560feffff080000008d9560feffff8d4db0ff15a8104000 }


condition:
	$a0
}