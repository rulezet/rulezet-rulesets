import "pe"
rule _Crunch_5__Fusion_4__BitArts_
{
	meta:
		description = "Crunch 5 / Fusion 4 -> Bit-Arts"
	strings:
		$0 = {EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}