import "pe"
rule _Microsoft_C_v104_
{
	meta:
		description = "Microsoft C v1.04"
	strings:
		$0 = {FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB}
	condition:
		$0 at pe.entry_point
}