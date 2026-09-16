import "pe"
rule _Adlib_Sample_Audio_file_
{
	meta:
		description = "Adlib Sample Audio file"
	strings:
		$0 = {47 4F 4C 44 20 53 41 4D 50 4C 45}
	condition:
		$0 at pe.entry_point
}