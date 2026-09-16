rule _Borland_Delphi_v50_KOLMCK_
{
	meta:
		description = "Borland Delphi v5.0 KOL/MCK"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF E8 FF FF E8 FF FF 8B}
	condition:
		$0 at entrypoint
}