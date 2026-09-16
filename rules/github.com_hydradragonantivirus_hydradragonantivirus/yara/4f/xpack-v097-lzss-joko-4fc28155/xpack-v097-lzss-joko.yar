import "pe"
rule _XPack_V097_LZSS__JoKo_
{
	meta:
		description = "XPack V0.97 (LZSS) -> JoKo"
	strings:
		$0 = {68 ?? ?? ?? 00 9C 60 E8 49 03 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 44 ?? ?? 00 34 ?? ?? 00 00 00}
	condition:
		$0 at pe.entry_point
}