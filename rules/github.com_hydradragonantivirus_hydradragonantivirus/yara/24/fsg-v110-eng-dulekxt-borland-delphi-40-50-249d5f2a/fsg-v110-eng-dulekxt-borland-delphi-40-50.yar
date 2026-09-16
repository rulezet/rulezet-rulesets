import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Delphi_40__50_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi 4.0 - 5.0)"
	strings:
		$0 = {EB 02}
	condition:
		$0 at pe.entry_point
}