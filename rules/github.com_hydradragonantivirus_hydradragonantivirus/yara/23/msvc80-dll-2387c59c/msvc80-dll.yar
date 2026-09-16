rule msvc80_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 8.0 DLL"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 10 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 FF 47 89 7D E4 }
	condition:
		$a0
}