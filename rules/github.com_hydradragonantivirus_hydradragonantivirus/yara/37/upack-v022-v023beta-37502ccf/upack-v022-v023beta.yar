import "pe"
rule _Upack_v022__v023Beta_
{
	meta:
		description = "Upack v0.22 ~ v0.23Beta"
	strings:
		$0 = {6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5}
	condition:
		$0 at pe.entry_point
}