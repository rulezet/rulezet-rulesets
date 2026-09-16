import "pe"
rule _Silicon_Realms_Install_Stub_Silicon_Realms_Toolworks_
{
	meta:
		description = "Silicon Realms Install Stub ->Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 50 92 40 00 68 E4 69 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 FC 90 40 00 33 D2 8A D4 89 15 94 E8 40 00 8B C8 81 E1 FF 00 00 00 89 0D 90 E8 40 00 C1 E1 08 03 CA 89 0D 8C E8 40 00 C1 E8 10 A3 88 E8 40 00 33 F6 56 E8 2F 0B 00 00 59 85 C0 75 08}
	condition:
		$0 at pe.entry_point
}