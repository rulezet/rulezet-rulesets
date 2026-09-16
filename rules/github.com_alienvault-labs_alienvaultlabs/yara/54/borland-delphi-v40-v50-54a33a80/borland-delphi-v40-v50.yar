rule _Borland_Delphi_v40__v50_
{
	meta:
		description = "Borland Delphi v4.0 - v5.0"
	strings:
		$0 = {55 8B EC 83}
		$1 = {50 6A ?? E8 FF FF BA 52 89 05 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 5A 58 E8}
		$2 = {BA 83 7D 0C 01 75 50 52 C6 05 8B 4D 08 89 0D 89 4A}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}