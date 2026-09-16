import "pe"
rule _LHA_Archive_
{
	meta:
		description = "LHA Archive"
	strings:
		$0 = {6C 68 35}
	condition:
		$0 at pe.entry_point
}