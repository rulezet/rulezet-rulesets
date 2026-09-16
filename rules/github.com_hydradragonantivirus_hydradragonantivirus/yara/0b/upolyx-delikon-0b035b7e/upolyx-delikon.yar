import "pe"
rule _UPolyX__delikon_
{
	meta:
		description = "UPolyX -> delikon"
	strings:
		$0 = {FF 96 ?? ?? ?? 00 61 E9 ?? ?? ?? FF}
	condition:
		$0 at pe.entry_point
}