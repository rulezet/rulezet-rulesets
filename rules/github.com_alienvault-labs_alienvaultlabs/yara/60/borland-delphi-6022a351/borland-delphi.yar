rule _Borland_Delphi_
{
	meta:
		description = "Borland Delphi"
	strings:
		$0 = {C3 E9 FF 8D}
	condition:
		$0 at entrypoint
}