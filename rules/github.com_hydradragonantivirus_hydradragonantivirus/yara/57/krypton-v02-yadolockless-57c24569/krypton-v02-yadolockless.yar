import "pe"
rule _Krypton_v02__yadolockless_
{
	meta:
		description = "Krypton v0.2 -> yado/lockless"
	strings:
		$0 = {8B 0C 24 E9 0A 7C 01 00 AD 42 40 BD BE 9D 7A 04}
	condition:
		$0 at pe.entry_point
}