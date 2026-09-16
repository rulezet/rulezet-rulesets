rule _Borland_Delphi_Setup_Module_
{
	meta:
		description = "Borland Delphi Setup Module"
	strings:
		$0 = {55 8B EC 83 C4}
	condition:
		$0 at entrypoint
}