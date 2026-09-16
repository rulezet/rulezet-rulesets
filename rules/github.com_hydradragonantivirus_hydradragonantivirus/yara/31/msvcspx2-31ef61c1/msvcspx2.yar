import "pe"
rule msvcspx2
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0 SPx Method 2"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }
	condition:
		$a0 at pe.entry_point
}