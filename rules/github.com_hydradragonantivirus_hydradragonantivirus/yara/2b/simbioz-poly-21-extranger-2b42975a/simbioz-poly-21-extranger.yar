import "pe"
rule _SimbiOZ_Poly_21__Extranger_
{
	meta:
		description = "SimbiOZ Poly 2.1 -> Extranger"
	strings:
		$0 = {55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90}
	condition:
		$0 at pe.entry_point
}