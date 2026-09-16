import "pe"
rule _IMPostor_Pack_10__Mahdi_Hezavehi_
{
	meta:
		description = "IMPostor Pack 1.0 -> Mahdi Hezavehi"
	strings:
		$0 = {BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00}
	condition:
		$0 at pe.entry_point
}