import "pe"
rule _PseudoSigner_01_REALBasic_
{
	meta:
		description = "PseudoSigner 0.1 [REALBasic"
	strings:
		$0 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9}
		$1 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}