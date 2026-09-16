import "pe"
rule _Microsoft_C_for_Windows_2_
{
	meta:
		description = "Microsoft C for Windows (2)"
	strings:
		$0 = {8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89}
	condition:
		$0 at pe.entry_point
}