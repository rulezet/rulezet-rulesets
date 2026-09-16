import "pe"
rule _Armadillo_v1xx__v2xx__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo v1.xx - v2.xx -> Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 50 8C 4C 00 68 D0 82 4A 00 64 A1}
	condition:
		$0 at pe.entry_point
}