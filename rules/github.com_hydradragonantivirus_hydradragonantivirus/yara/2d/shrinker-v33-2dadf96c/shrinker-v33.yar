import "pe"
rule _Shrinker_v33_
{
	meta:
		description = "Shrinker v3.3"
	strings:
		$0 = {83 3D B4 55 8B EC 56 57 75 6B 68 ?? 01 ?? ?? E8 0B ?? ?? 83 C4 04 8B 75 08 A3 B4 85 F6 74 23 83 7D 0C 03 77 1D 68}
	condition:
		$0 at pe.entry_point
}