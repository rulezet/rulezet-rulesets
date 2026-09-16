import "pe"
rule _MicroJoiner_v15__coban2k_
{
	meta:
		description = "MicroJoiner v1.5 -> coban2k"
	strings:
		$0 = {BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF}
	condition:
		$0 at pe.entry_point
}