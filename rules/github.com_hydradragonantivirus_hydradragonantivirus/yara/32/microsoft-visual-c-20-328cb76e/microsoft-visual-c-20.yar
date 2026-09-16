import "pe"
rule _Microsoft_Visual_C_20_
{
	meta:
		description = "Microsoft Visual C 2.0"
	strings:
		$0 = {64 A1 00 00 00 00 55 8B EC 6A FF 68}
		$1 = {53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}