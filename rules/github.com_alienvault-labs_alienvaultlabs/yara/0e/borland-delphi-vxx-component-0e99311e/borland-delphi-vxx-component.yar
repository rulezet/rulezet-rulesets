rule _Borland_Delphi_vxx_Component_
{
	meta:
		description = "Borland Delphi vx.x (Component)"
	strings:
		$0 = {55 8B EC 83 C4 B4 B8 E8 E8 8D}
	condition:
		$0 at entrypoint
}