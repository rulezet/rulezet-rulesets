import "pe"
rule _ACESFX_Archive_
{
	meta:
		description = "ACE-SFX Archive"
	strings:
		$0 = {2A 2A 41 43 45 2A 2A}
	condition:
		$0 at pe.entry_point
}