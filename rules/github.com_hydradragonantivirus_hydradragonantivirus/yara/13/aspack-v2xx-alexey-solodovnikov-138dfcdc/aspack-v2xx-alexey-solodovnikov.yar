import "pe"
rule _ASPack_v2xx__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v2.xx -> Alexey Solodovnikov"
	strings:
		$0 = {A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95}
		$1 = {A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}