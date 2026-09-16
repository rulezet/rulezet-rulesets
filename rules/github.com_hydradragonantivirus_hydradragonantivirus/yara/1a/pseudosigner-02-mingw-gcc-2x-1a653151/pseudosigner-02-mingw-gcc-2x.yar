import "pe"
rule _PseudoSigner_02_MinGW_GCC_2x_
{
	meta:
		description = "PseudoSigner 0.2 [MinGW GCC 2.x"
	strings:
		$0 = {55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45}
	condition:
		$0 at pe.entry_point
}