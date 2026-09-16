import "pe"
rule _PEtite_v13_
{
	meta:
		description = "PEtite v1.3"
	strings:
		$0 = {66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B}
	condition:
		$0 at pe.entry_point
}