import "pe"
rule _CICompress_v10_
{
	meta:
		description = "CICompress v1.0"
	strings:
		$0 = {90 61 BE ?? 10 42 ?? 8D BE ?? ?? FE FF C7 87 C0 20 02 ?? F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E}
	condition:
		$0 at pe.entry_point
}