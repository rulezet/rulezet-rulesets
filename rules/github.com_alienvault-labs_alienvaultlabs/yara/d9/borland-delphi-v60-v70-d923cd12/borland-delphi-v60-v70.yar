rule _Borland_Delphi_v60__v70_
{
	meta:
		description = "Borland Delphi v6.0 - v7.0"
	strings:
		$0 = {E8 6A E8 89 05 E8 89 05 C7 05 0A B8}
		$1 = {53 8B D8 33 C0 A3 ?? 6A ?? E8 ?? FF A3 ?? A1 ?? A3 ?? 33 C0 A3 ?? 33 C0 A3 ??}
		$2 = {55 8B EC B9 6A ?? 6A ??}
		$3 = {55 8B EC 83 C4 F0 B8 E8 FB FF A1 8B E8 FF FF 8B 0D A1 8B ?? 8B 15 E8 FF FF A1 8B E8 FF}
		$4 = {55 8B EC}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint or $4 at entrypoint
}