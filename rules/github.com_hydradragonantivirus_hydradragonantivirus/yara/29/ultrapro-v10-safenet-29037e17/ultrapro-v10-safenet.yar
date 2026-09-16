import "pe"
rule _UltraPro_V10__SafeNet_
{
	meta:
		description = "UltraPro V1.0 -> SafeNet"
	strings:
		$0 = {A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15}
	condition:
		$0 at pe.entry_point
}