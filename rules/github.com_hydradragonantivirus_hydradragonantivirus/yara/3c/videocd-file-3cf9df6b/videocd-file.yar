import "pe"
rule _VideoCD_file_
{
	meta:
		description = "Video-CD file"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 43 44 58 41 66 6D 74}
	condition:
		$0 at pe.entry_point
}