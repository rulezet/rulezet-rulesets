import "pe"
rule _Borland_Delphi_6070_
{
	meta:
		description = "Borland Delphi 6.0-7.0"
	strings:
		$0 = {55 8B EC 83 C4 ?? 53 33 C0}
	condition:
		$0 at pe.entry_point
}