import "pe"
rule _ASPack_v102b_
{
	meta:
		description = "ASPack v1.02b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03}
		$1 = {60 E8 5D 81 ED AE 98 43 B8 A8 98 43 03 C5 2B 85 18 9D 43 89 85 24 9D 43 80 BD 0E 9D}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}