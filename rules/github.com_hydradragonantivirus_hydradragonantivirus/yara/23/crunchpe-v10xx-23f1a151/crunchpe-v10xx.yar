import "pe"
rule _CrunchPE_v10xx_
{
	meta:
		description = "Crunch/PE v1.0.x.x"
	strings:
		$0 = {55 E8 5D 83 ED 06 8B C5 55 60 89 AD 2B 85 89 85 55 BB 03 DD 53 64 67 FF 36 64 67 89}
	condition:
		$0 at pe.entry_point
}