import "pe"
rule _KByS_V028_DLL__shoooo__Sign_by_fly_
{
	meta:
		description = "KByS V0.28 DLL -> shoooo ! Sign by fly"
	strings:
		$0 = {B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}