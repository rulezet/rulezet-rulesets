rule _Borland_Delphi_DLL_
{
	meta:
		description = "Borland Delphi DLL"
	strings:
		$0 = {55 8B EC 83}
	condition:
		$0 at entrypoint
}