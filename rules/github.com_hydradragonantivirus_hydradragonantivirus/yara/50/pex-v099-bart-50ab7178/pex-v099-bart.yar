import "pe"
rule _PEX_v099__bart_
{
	meta:
		description = "PEX v0.99 -> bart"
	strings:
		$0 = {68 FA 30 41 00 C3 20 20}
	condition:
		$0 at pe.entry_point
}