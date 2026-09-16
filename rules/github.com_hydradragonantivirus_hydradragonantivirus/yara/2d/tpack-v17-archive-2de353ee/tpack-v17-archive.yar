import "pe"
rule _TPACK_v17_Archive_
{
	meta:
		description = "TPACK v1.7 Archive"
	strings:
		$0 = {54 50 41 43 ?? 31 2E 37}
	condition:
		$0 at pe.entry_point
}