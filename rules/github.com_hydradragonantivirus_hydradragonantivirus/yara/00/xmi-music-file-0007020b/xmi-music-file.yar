import "pe"
rule _XMI_music_file_
{
	meta:
		description = "XMI music file"
	strings:
		$0 = {46 4F 52 4D ?? ?? ?? ?? 58 4D 49 44}
	condition:
		$0 at pe.entry_point
}