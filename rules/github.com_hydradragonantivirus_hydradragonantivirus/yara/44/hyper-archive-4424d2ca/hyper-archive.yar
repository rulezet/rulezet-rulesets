import "pe"
rule _Hyper_Archive_
{
	meta:
		description = "Hyper Archive"
	strings:
		$0 = {1A 53 54}
		$1 = {1A 48 50}
	condition:
		$0 at pe.entry_point or $1
}