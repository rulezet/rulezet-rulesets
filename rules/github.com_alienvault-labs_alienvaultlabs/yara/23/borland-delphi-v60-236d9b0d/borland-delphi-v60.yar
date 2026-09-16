rule _Borland_Delphi_v60_
{
	meta:
		description = "Borland Delphi v6.0"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 45 ?? E8 FF A1 45 ?? 8B ?? E8 FF FF 8B}
		$1 = {55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF A1 72 40 ?? 33 D2 E8 FF FF A1 72 40 ?? 8B ?? 83 C0 14 E8 FF FF E8 FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}