import "pe"
rule _PseudoSigner_01_ASProtect_
{
	meta:
		description = "PseudoSigner 0.1 [ASProtect"
	strings:
		$0 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9}
		$1 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}