import "pe"
rule _pirit_v15_
{
	meta:
		description = "$pirit v1.5"
	strings:
		$0 = {5B 24 55 50 44 FB 32 2E 31 5D}
	condition:
		$0 at pe.entry_point
}