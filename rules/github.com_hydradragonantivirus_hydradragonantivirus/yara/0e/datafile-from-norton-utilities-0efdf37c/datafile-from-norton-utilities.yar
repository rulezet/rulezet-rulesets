import "pe"
rule _Datafile_from_Norton_Utilities_
{
	meta:
		description = "Datafile from Norton Utilities"
	strings:
		$0 = {50 4E 43 49}
	condition:
		$0 at pe.entry_point
}