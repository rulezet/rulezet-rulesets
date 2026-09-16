import "pe"
rule _Armadillo_v200b1__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo v2.00b1 -> Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 00 F2 40 00 68 C4 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58}
	condition:
		$0 at pe.entry_point
}