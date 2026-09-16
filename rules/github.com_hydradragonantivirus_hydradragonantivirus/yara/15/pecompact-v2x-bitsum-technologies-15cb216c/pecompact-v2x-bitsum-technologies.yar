import "pe"
rule _PECompact_V2X__Bitsum_Technologies_
{
	meta:
		description = "PECompact V2.X -> Bitsum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}
	condition:
		$0 at pe.entry_point
}