import "pe"
rule _Borland_Delphi_40_
{
	meta:
		description = "Borland Delphi 4.0"
	strings:
		$0 = {55 8B EC 83 C4}
	condition:
		$0 at pe.entry_point
}