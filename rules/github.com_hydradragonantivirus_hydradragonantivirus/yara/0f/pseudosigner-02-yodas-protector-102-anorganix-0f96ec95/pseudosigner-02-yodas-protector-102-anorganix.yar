import "pe"
rule _PseudoSigner_02_Yodas_Protector_102__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Yoda's Protector 1.02] --> Anorganix"
	strings:
		$0 = {E8 03 00 00 00 EB 01 90 90}
	condition:
		$0 at pe.entry_point
}