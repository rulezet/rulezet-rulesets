import "pe"
rule _MicroJoiner_11__coban2k_
{
	meta:
		description = "MicroJoiner 1.1 -> coban2k"
	strings:
		$0 = {BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11}
	condition:
		$0 at pe.entry_point
}