import "pe"
rule _RAR_Archive_
{
	meta:
		description = "RAR Archive"
	strings:
		$0 = {52 61 72 21}
	condition:
		$0 at pe.entry_point
}