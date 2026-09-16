import "pe"
rule _RAR_Configuration_file_
{
	meta:
		description = "RAR Configuration file"
	strings:
		$0 = {52 41 52 20 43 4F 4E 46 49 47}
	condition:
		$0 at pe.entry_point
}