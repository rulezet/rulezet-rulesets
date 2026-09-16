import "pe"
rule _MASMTASM_
{
	meta:
		description = "MASM/TASM"
	strings:
		$0 = {6A 00 E8 ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}