import "pe"
rule _File_Analyzer_Registration_file_v10_
{
	meta:
		description = "File Analyzer Registration file v1.0"
	strings:
		$0 = {24 46 41 52 45 47 24 4D 2D ?? ?? ?? ?? 31}
	condition:
		$0 at pe.entry_point
}