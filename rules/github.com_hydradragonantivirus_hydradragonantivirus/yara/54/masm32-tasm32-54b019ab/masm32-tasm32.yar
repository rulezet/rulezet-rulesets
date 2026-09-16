import "pe"
rule _MASM32__TASM32_
{
	meta:
		description = "MASM32 / TASM32"
	strings:
		$0 = {2B C0 50 E8}
	condition:
		$0 at pe.entry_point
}