import "pe"
rule _Upack_v033__v034_Beta__Dwing_
{
	meta:
		description = "Upack v0.33 ~ v0.34 Beta -> Dwing"
	strings:
		$0 = {59 F3 A5 83 C8 FF 8B DF AB 40 AB 40}
	condition:
		$0 at pe.entry_point
}