import "pe"
rule _MS_Compress_Archive_
{
	meta:
		description = "MS Compress Archive"
	strings:
		$0 = {53 5A 44 44}
	condition:
		$0 at pe.entry_point
}