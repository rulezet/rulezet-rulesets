import "pe"
rule _id_Softwares_WAD_file_
{
	meta:
		description = "id Software's WAD file"
	strings:
		$0 = {50 57 41 44 0B 00}
	condition:
		$0 at pe.entry_point
}