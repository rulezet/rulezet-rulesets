import "pe"
rule _UPolyx_05_by_delikon_
{
	meta:
		description = "UPolyx 0.5 by delikon"
	strings:
		$0 = {51 ?? C9 B9 ?? ?? ?? ?? 83 ?? 01 E2}
	condition:
		$0 at pe.entry_point
}