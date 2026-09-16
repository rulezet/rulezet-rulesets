rule _LCC_Win32_DLL_
{
	meta:
		description = "LCC Win32 DLL"
	strings:
		$0 = {8B 44 24 08 56 83 E8 74 48}
	condition:
		$0 at entrypoint
}