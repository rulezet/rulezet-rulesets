rule _LCC_Win32_v1x_
{
	meta:
		description = "LCC Win32 v1.x"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 FF 75 10 FF 75 0C FF 75 08}
	condition:
		$0 at entrypoint
}