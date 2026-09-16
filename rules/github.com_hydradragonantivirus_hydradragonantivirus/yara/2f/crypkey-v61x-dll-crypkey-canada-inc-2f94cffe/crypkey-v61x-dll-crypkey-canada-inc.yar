import "pe"
rule _CrypKey_V61X_DLL__CrypKey_Canada_Inc_
{
	meta:
		description = "CrypKey V6.1X DLL -> CrypKey (Canada) Inc."
	strings:
		$0 = {83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8}
	condition:
		$0 at pe.entry_point
}