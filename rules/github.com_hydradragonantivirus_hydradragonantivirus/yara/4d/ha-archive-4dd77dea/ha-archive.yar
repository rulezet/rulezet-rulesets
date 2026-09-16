import "pe"
rule _HA_Archive_
{
	meta:
		description = "HA Archive"
	strings:
		$0 = {48 41}
	condition:
		$0 at pe.entry_point
}