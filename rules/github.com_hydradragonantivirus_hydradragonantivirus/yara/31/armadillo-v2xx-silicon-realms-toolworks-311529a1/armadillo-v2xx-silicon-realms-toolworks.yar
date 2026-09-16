import "pe"
rule _Armadillo_v2xx__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo v2.xx -> Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 F0 67 4D 00 68 50 92 4B 00 64 A1}
	condition:
		$0 at pe.entry_point
}