rule _Borland_Delphi_v30_
{
	meta:
		description = "Borland Delphi v3.0"
	strings:
		$0 = {55 8B EC 83}
		$1 = {50 6A E8 FF FF BA 52 89 05 89 42 04 C7 42 08 C7 42 0C E8 5A 58 E8}
	condition:
		$0 at entrypoint or $1 at entrypoint
}