rule _Borland_Delphi_v20_
{
	meta:
		description = "Borland Delphi v2.0"
	strings:
		$0 = {50 6A E8 FF FF BA 52 89 05 89 42 04 E8 5A 58 E8 C3 55 8B EC 33}
	condition:
		$0 at entrypoint
}