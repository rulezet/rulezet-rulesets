import "pe"
rule _File_Analyzer_Extended_Datafile_
{
	meta:
		description = "File Analyzer Extended Datafile"
	strings:
		$0 = {23 03 45 58 54 44}
	condition:
		$0 at pe.entry_point
}