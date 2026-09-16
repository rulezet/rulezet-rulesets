import "pe"
rule _PECompact_092_
{
	meta:
		description = "PECompact 0.92"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 BD 00 00 00 00 B9 02 00 00 00 B0 90 8D BD A5 4F 40 00 F3 AA 01 AD 04 51 40 00 FF B5 00 51 40 00 6A 40 FF 95 38 51 40 00 50 50 2D F7 4F 40 00 89 85 F8 4F 40 00 5F 8D B5 F7 4F 40 00 B9 35 03 00 00 F3 A5 5F 8B D7}
	condition:
		$0 at pe.entry_point
}