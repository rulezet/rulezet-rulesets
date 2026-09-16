import "pe"
rule _Reflexive_Arcade_Installer_
{
	meta:
		description = "Reflexive Arcade Installer"
	strings:
		$0 = {55 8B EC 6A FF 68 98 48 42 00 68 B4 DC 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 31 42 00 33 D2 8A D4 89 15 8C CA 42 00 8B C8 81 E1 FF 00 00 00 89 0D}
	condition:
		$0 at pe.entry_point
}