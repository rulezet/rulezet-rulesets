import "pe"
rule _VcasmProtector_10a__10d__vcasm_
{
	meta:
		description = "Vcasm-Protector 1.0a - 1.0d -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00}
	condition:
		$0 at pe.entry_point
}