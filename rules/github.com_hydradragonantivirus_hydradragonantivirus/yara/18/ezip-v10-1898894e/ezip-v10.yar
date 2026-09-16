import "pe"
rule _EZIP_v10_
{
	meta:
		description = "EZIP v1.0"
	strings:
		$0 = {BB D0 01 40 ?? BF ?? 10 40 ?? BE 53 E8 0A ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02}
	condition:
		$0 at pe.entry_point
}