import "pe"
rule _Microsoft_R_Fulltext_index_file_
{
	meta:
		description = "Microsoft (R) Full-text index file"
	strings:
		$0 = {6C 6C 2D 74 65 78 74 20 69 6E 64 65 78}
	condition:
		$0 at pe.entry_point
}