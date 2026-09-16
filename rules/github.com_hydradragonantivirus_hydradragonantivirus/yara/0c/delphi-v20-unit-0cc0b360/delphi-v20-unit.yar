import "pe"
rule _Delphi_v20_Unit_
{
	meta:
		description = "Delphi v2.0 Unit"
	strings:
		$0 = {44 43 55 32}
	condition:
		$0 at pe.entry_point
}