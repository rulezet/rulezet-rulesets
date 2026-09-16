import "pe"
rule _ORiEN_V212__Fisun_AV_
{
	meta:
		description = "ORiEN V2.12 -> Fisun A.V."
	strings:
		$0 = {E9 5D 01 00 00 CE D1 CE CD 0D}
	condition:
		$0 at pe.entry_point
}