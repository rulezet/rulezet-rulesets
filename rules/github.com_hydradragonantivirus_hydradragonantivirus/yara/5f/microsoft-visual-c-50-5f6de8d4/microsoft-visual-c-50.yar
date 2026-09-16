import "pe"
rule _Microsoft_Visual_C_50_
{
	meta:
		description = "Microsoft Visual C 5.0"
	strings:
		$0 = {64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57}
	condition:
		$0 at pe.entry_point
}