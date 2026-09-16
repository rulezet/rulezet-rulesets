import "pe"
rule _XoReR_10_
{
	meta:
		description = "XoReR 1.0"
	strings:
		$0 = {BE 00 00 8B FE B9 6B 00 33 DB 80 C3 00 AC 32 C3 AA E2 F7}
	condition:
		$0 at pe.entry_point
}