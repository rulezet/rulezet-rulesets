import "pe"
rule _PseudoSigner_01_PECompact_14p__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PECompact 1.4+] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81}
	condition:
		$0 at pe.entry_point
}