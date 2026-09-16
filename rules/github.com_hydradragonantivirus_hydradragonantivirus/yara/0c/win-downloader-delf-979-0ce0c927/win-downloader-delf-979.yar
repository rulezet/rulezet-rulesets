rule Win_Downloader_Delf_979
{
strings:
	$a0 = { 41ad43ce1d3899382e7576f8ffd6465780e34905a6f4602c02416ef0ffbd29b314675fb8ea0d281dc834b7506564e4723a50a8b1fe6be3e8a7cc6fdac0cf04839fb7c91190e8 }


condition:
	$a0
}