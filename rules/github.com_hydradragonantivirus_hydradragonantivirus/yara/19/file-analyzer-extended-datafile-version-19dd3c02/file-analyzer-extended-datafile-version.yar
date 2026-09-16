import "pe"
rule _File_Analyzer_Extended_Datafile_Version_
{
	meta:
		description = "File Analyzer Extended Datafile Version"
	strings:
		$0 = {23 03 45 58 54 44 ?? ?? 3A 03}
	condition:
		$0 at pe.entry_point
}