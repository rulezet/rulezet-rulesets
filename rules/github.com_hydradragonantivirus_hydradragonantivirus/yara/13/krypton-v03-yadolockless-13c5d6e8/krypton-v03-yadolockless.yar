import "pe"
rule _Krypton_v03__yadolockless_
{
	meta:
		description = "Krypton v0.3 -> yado/lockless"
	strings:
		$0 = {8B 0C 24 E9 C0 8D 01 00 C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA}
	condition:
		$0 at pe.entry_point
}