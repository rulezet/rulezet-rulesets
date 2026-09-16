import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Cpp_60_Debug_Version__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 6.0 (Debug Version)] --> Anorganix"
	strings:
		$0 = {55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}