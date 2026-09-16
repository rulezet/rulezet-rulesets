import "pe"
rule _TASM__MASM_
{
	meta:
		description = "TASM / MASM"
	strings:
		$0 = {E9 E5 E2 FF}
	condition:
		$0 at pe.entry_point
}