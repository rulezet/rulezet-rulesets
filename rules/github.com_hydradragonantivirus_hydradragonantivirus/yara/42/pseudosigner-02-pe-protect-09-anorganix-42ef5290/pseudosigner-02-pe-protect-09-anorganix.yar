import "pe"
rule _PseudoSigner_02_PE_Protect_09__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PE Protect 0.9] --> Anorganix"
	strings:
		$0 = {52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3}
	condition:
		$0 at pe.entry_point
}