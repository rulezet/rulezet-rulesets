rule Win_Downloader_Swizzor_304
{
strings:
	$a0 = { bf4f0fd016cf9edf25dd68ecb2bf2cfea57fdfa646210d901bc16584191dd0f343217a69b496a9d74cc744b4b8850fa9 }


condition:
	$a0
}