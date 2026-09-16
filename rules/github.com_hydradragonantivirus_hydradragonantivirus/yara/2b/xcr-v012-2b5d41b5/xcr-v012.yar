import "pe"
rule _XCR_v012_
{
	meta:
		description = "XCR v0.12"
	strings:
		$0 = {93 71 08 8B D8 78 E2 9C 33 C3 60 79 CE E8 01 83 C4 04 E8 AB FF FF FF 2B E8 03 C5 FF}
	condition:
		$0 at pe.entry_point
}