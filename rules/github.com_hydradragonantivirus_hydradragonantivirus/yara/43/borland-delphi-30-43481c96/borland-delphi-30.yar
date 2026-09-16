import "pe"
rule _Borland_Delphi_30__
{
	meta:
		description = "Borland Delphi 3.0 (???)"
	strings:
		$0 = {55 8B EC 83}
	condition:
		$0 at pe.entry_point
}