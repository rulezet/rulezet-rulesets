import "pe"
rule _FIZ_Archive_
{
	meta:
		description = "FIZ Archive"
	strings:
		$0 = {46 49 5A 1A 01}
	condition:
		$0 at pe.entry_point
}