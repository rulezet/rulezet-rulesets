import "pe"
rule _PseudoSigner_01_UPX_06_
{
	meta:
		description = "PseudoSigner 0.1 [UPX 0.6"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9}
		$1 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}