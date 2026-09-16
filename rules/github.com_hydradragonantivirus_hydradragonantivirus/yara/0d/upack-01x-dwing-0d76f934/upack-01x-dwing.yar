import "pe"
rule _Upack_01x__Dwing_
{
	meta:
		description = "Upack 0.1x -> Dwing"
	strings:
		$0 = {BE 48 01 40 00 AD 8B F8}
	condition:
		$0 at pe.entry_point
}