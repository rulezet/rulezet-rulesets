rule _Borland_Delphi_v50_KOL_
{
	meta:
		description = "Borland Delphi v5.0 KOL"
	strings:
		$0 = {53 8B D8 33 C0 A3 6A ?? E8 FF A3 A1 A3 33 C0 A3 33 C0 A3}
	condition:
		$0 at entrypoint
}