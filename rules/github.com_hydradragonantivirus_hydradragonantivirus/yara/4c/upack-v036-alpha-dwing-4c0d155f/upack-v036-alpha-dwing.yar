rule _Upack_v036_alpha__Dwing_
{
	meta:
		description = "Upack v0.36 alpha -> Dwing"
	strings:
		$0 = {AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0}
	condition:
		$0
}