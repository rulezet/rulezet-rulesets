import "pe"
rule _TPPpack__clane_
{
	meta:
		description = "TPPpack -> clane"
	strings:
		$0 = {E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8}
	condition:
		$0 at pe.entry_point
}