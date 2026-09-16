import "pe"
rule _MASM__TASM_
{
	meta:
		description = "MASM / TASM"
	strings:
		$0 = {6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00}
		$1 = {53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}