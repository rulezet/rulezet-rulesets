import "pe"
rule ms_vc_h
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 }
	condition:
		$a0 at pe.entry_point
}