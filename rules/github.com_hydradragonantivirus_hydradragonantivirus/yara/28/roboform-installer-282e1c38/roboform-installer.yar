import "pe"
rule _RoboForm_Installer_
{
	meta:
		description = "RoboForm Installer"
	strings:
		$0 = {55 8B EC 6A FF 68 E0 F3 40 00 68 44 90 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 68 F0 40 00 33 D2 8A D4 89 15 04 6B 41 00 8B C8 81 E1 FF 00 00 00 89 0D}
	condition:
		$0 at pe.entry_point
}