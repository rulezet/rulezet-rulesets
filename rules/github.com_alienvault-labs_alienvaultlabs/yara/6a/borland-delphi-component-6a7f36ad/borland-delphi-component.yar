rule _Borland_Delphi_Component_
{
	meta:
		description = "Borland Delphi (Component)"
	strings:
		$0 = {55 89 E5 83 EC 04 83}
	condition:
		$0 at entrypoint
}