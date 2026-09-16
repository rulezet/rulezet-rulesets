import "pe"
rule _CrypKey_V56X_DLL__Kenonic_Controls_Ltd_
{
	meta:
		description = "CrypKey V5.6.X DLL -> Kenonic Controls Ltd."
	strings:
		$0 = {8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8}
	condition:
		$0 at pe.entry_point
}