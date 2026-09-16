import "pe"
rule aspack_107b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.07b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 0B DE ?? ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
	condition:
		$a0 at pe.entry_point
}