import "pe"
rule _Delphi_v10_Unit_
{
	meta:
		description = "Delphi v1.0 Unit"
	strings:
		$0 = {44 43 55 31}
	condition:
		$0 at pe.entry_point
}