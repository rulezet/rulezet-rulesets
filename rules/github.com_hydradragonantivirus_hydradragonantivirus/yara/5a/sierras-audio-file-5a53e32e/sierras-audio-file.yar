import "pe"
rule _Sierras_audio_file_
{
	meta:
		description = "Sierra`s audio file"
	strings:
		$0 = {8D 0C 53 4F 4C 00 22 56 0D}
	condition:
		$0 at pe.entry_point
}