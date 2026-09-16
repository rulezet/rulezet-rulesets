import "pe"
rule _PseudoSigner_01_DxPack_10_
{
	meta:
		description = "PseudoSigner 0.1 [DxPack 1.0"
	strings:
		$0 = {60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9}
		$1 = {60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}