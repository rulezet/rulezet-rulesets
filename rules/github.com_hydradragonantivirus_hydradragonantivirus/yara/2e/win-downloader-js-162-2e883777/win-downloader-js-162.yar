rule Win_Downloader_JS_162
{
strings:
	$a0 = { 77696e646f772e6c6f636174696f6e3d2822[0-26]2f676f2e7068703f7369643d3122293b }


condition:
	$a0
}