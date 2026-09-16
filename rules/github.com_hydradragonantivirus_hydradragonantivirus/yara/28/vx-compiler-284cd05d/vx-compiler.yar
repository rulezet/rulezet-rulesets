import "pe"
rule _Vx_Compiler_
{
	meta:
		description = "Vx: Compiler"
	strings:
		$0 = {8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E}
	condition:
		$0 at pe.entry_point
}