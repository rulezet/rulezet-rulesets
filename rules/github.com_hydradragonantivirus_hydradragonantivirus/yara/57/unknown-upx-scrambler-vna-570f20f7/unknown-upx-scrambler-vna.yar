import "pe"
rule _Unknown_UPX_Scrambler_vna_
{
	meta:
		description = "Unknown_UPX_Scrambler vna"
	strings:
		$0 = {C7 45 FC ?? ?? ?? ?? 6A 04 6A 00 6A 00 68 FF FF FB FF FF 15 ?? ?? ?? ?? 85 C0 7E ?? 6A 00 FF 15 ?? ?? ?? ?? 8B 45 FC 8B 40 04 83 E8 03 8B 4D FC 89 41 04 83 65 F4 00 EB ?? 8B 45 F4 40 89 45 F4 8B 45 FC 8B 4D F4 3B 48 04 73 ?? 8B 45 FC 8B 40 04 2B 45 F4 8B 4D FC 8B 09 8B 55 FC 8B 44 01 FF 33 42 0C 8B 4D FC 8B 49 04 2B 4D F4 8B 55 FC 8B 12 89 44 11 FF EB ?? 8B 45 FC 8B 40 08 89 45 F8 8B 45 F8}
	condition:
		$0 at pe.entry_point
}