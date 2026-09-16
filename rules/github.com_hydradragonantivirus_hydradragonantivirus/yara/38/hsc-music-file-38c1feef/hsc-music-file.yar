import "pe"
rule _HSC_music_file_
{
	meta:
		description = "HSC music file"
	strings:
		$0 = {C8 E2 04 20}
	condition:
		$0 at pe.entry_point
}