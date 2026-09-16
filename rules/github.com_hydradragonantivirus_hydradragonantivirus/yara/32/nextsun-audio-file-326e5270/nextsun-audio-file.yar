import "pe"
rule _NextSun_Audio_file_
{
	meta:
		description = "Next/Sun Audio file"
	strings:
		$0 = {2E 73 6E 64}
	condition:
		$0 at pe.entry_point
}