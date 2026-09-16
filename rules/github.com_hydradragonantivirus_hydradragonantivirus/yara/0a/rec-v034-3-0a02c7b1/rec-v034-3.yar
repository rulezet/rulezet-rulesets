import "pe"
rule _REC_v034_3_
{
	meta:
		description = "REC v0.34 [3"
	strings:
		$0 = {06 1E B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB}
	condition:
		$0 at pe.entry_point
}