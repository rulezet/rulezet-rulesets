import "pe"
rule _Microsoft_WAV_Audio_file_
{
	meta:
		description = "Microsoft WAV Audio file"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74}
	condition:
		$0 at pe.entry_point
}