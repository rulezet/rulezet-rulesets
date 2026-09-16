import "pe"
rule _HPACK_Archive_
{
	meta:
		description = "HPACK Archive"
	strings:
		$0 = {48 50 41 4B}
	condition:
		$0 at pe.entry_point
}