import "pe"
rule _MS_HTMLHelp_file_
{
	meta:
		description = "MS HTML-Help file"
	strings:
		$0 = {49 54 53 46}
	condition:
		$0 at pe.entry_point
}