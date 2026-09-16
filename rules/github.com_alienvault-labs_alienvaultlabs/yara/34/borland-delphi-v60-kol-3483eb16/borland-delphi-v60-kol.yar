rule _Borland_Delphi_v60_KOL_
{
	meta:
		description = "Borland Delphi v6.0 KOL"
	strings:
		$0 = {55 8B EC 83 C4 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0}
	condition:
		$0 at entrypoint
}