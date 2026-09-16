import "pe"
rule _NsPack_14__Liuxingping_
{
	meta:
		description = "NsPack 1.4 -> Liuxingping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00}
	condition:
		$0 at pe.entry_point
}