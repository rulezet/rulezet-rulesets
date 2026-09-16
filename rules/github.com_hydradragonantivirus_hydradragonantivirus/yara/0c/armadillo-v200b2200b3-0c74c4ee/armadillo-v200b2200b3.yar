import "pe"
rule _Armadillo_v200b2200b3_
{
	meta:
		description = "Armadillo v2.00b2-2.00b3"
	strings:
		$0 = {55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at pe.entry_point
}