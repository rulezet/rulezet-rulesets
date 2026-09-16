import "pe"
rule _PseudoSigner_01_PESHiELD_025_
{
	meta:
		description = "PseudoSigner 0.1 [PESHiELD 0.25"
	strings:
		$0 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9}
		$1 = {60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}