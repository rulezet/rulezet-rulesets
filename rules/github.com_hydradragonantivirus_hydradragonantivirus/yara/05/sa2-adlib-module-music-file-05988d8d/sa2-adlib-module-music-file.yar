import "pe"
rule _SA2_Adlib_Module_music_file_
{
	meta:
		description = "SA2 Adlib Module music file"
	strings:
		$0 = {53 41 64 54}
	condition:
		$0 at pe.entry_point
}