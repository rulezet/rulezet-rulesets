import "pe"
rule _NeoLite_v10_
{
	meta:
		description = "NeoLite v1.0"
	strings:
		$0 = {8B 44 24 04 8D 54 24 FC 23 05 E8 FF 35 50 FF}
	condition:
		$0 at pe.entry_point
}