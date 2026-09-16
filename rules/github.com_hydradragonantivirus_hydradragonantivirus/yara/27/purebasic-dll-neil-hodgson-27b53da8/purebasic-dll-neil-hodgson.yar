import "pe"
rule _PureBasic_DLL__Neil_Hodgson_
{
	meta:
		description = "PureBasic DLL -> Neil Hodgson"
	strings:
		$0 = {83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8}
	condition:
		$0 at pe.entry_point
}