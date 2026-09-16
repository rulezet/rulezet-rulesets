import "pe"
rule _Interplays_MVE_file_
{
	meta:
		description = "Interplay's MVE file"
	strings:
		$0 = {49 6E 74 65 72 70 6C 61 79 20 4D 56 45 20 46 69 6C 65 1A 00 1A}
	condition:
		$0 at pe.entry_point
}