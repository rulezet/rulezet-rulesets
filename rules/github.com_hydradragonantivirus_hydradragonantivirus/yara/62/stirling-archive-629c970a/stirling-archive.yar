import "pe"
rule _Stirling_Archive_
{
	meta:
		description = "Stirling Archive"
	strings:
		$0 = {13 5D 65 8C 3A}
	condition:
		$0 at pe.entry_point
}