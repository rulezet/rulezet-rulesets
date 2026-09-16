import "pe"
rule _Upack_v01x__v02x__Dwing_
{
	meta:
		description = "Upack v0.1x - v0.2x -> Dwing"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 95}
	condition:
		$0 at pe.entry_point
}