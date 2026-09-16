import "pe"
rule _PseudoSigner_01_LCC_Win32_DLL_
{
	meta:
		description = "PseudoSigner 0.1 [LCC Win32 DLL"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9}
		$1 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}