import "pe"
rule lockless
{
	meta:
		author = "PEiD"
		description = "Lockless Intro Packer [Krypton Mod.] -> Yado"
		group = "129"
		function = "0"
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }
	condition:
		$a0 at pe.entry_point
}