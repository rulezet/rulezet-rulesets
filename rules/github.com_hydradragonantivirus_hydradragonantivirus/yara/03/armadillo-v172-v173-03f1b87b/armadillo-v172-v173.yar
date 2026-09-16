import "pe"
rule _Armadillo_v172__v173_
{
	meta:
		description = "Armadillo v1.72 - v1.73"
	strings:
		$0 = {55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58}
	condition:
		$0 at pe.entry_point
}