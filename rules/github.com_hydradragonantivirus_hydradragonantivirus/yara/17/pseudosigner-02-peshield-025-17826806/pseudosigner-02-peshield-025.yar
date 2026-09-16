import "pe"
rule _PseudoSigner_02_PESHiELD_025_
{
	meta:
		description = "PseudoSigner 0.2 [PESHiELD 0.25"
	strings:
		$0 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC}
	condition:
		$0 at pe.entry_point
}