import "pe"
rule _PUNiSHER_V15_Demo_FEUERRADER_
{
	meta:
		description = "PUNiSHER V1.5 Demo-> FEUERRADER"
	strings:
		$0 = {EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}