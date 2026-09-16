import "pe"
rule _WWPack_Mutator_11c_
{
	meta:
		description = "WWPack Mutator 1.1c"
	strings:
		$0 = {00 00 00 00 00 00 00 00 2E 80 00 00 00 00 00 00 00 75 F5}
	condition:
		$0 at pe.entry_point
}