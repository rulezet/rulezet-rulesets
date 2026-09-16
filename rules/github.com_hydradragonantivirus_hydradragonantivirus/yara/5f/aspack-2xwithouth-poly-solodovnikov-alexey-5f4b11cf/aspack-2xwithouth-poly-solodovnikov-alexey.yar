import "pe"
rule _ASPack_2xwithouth_Poly__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 2.x(withouth Poly) -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB EC FF FF FF 03 DD 81 EB 00 40 1C 00}
	condition:
		$0 at pe.entry_point
}