import "pe"
rule _FASM_15x_
{
	meta:
		description = "FASM 1.5x"
	strings:
		$0 = {6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00}
	condition:
		$0 at pe.entry_point
}