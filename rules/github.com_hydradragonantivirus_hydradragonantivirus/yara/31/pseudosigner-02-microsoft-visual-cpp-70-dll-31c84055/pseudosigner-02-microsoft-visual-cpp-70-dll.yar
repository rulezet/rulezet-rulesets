import "pe"
rule _PseudoSigner_02_Microsoft_Visual_Cpp_70_DLL_
{
	meta:
		description = "PseudoSigner 0.2 [Microsoft Visual C++ 7.0 DLL"
	strings:
		$0 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84}
		$1 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}