import "pe"
rule _ASPack_212withouth_Poly__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 2.12(withouth Poly) -> Solodovnikov Alexey"
	strings:
		$0 = {E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01}
	condition:
		$0 at pe.entry_point
}