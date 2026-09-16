import "pe"
rule _FSG_v12_
{
	meta:
		description = "FSG v1.2"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE 53 E8 0A ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14}
	condition:
		$0 at pe.entry_point
}