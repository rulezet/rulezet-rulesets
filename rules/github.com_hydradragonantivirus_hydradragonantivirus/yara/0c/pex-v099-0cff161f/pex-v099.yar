import "pe"
rule _PEX_v099_
{
	meta:
		description = "PEX v0.99"
	strings:
		$0 = {60 E8 01 83 C4 04 E8 01 5D}
		$1 = {55 8B EC A1 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}