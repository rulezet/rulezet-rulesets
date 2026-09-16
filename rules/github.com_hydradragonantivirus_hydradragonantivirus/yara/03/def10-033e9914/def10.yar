import "pe"
rule DEF10 : bart xt
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { BE ?? ?? ?? ?? 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point
}