import "pe"
rule _32Lite_v003a__Oleg_Prokhorov_
{
	meta:
		description = "32Lite v0.03a -> Oleg Prokhorov"
	strings:
		$0 = {60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 00 10 ?? ?? 68}
	condition:
		$0 at pe.entry_point
}