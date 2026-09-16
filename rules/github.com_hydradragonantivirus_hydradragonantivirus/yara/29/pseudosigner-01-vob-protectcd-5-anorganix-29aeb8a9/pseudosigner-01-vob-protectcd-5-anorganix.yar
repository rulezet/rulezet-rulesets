import "pe"
rule _PseudoSigner_01_VOB_ProtectCD_5__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [VOB ProtectCD 5] --> Anorganix"
	strings:
		$0 = {36 3E 26 8A C0 60 E8 00 00 00 00 E9}
	condition:
		$0 at pe.entry_point
}