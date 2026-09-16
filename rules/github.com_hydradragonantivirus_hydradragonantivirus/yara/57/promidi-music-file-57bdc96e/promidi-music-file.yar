import "pe"
rule _PROMIDI_Music_file_
{
	meta:
		description = "PRO-MIDI Music file"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 52 4D 49 44}
	condition:
		$0 at pe.entry_point
}