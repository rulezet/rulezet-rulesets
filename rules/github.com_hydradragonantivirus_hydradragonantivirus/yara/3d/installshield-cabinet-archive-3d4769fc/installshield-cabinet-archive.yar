import "pe"
rule _InstallShield_Cabinet_Archive_
{
	meta:
		description = "InstallShield Cabinet Archive"
	strings:
		$0 = {49 53 63}
	condition:
		$0 at pe.entry_point
}