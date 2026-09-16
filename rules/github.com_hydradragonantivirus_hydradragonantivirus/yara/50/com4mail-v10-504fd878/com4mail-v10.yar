import "pe"
rule _Com4mail_v10_
{
	meta:
		description = "Com4mail v1.0"
	strings:
		$0 = {42 45 47 49 4E 3D 3D 3D 74 66 75 64 23 6F 66 5F 43 6F 6D 34 4D 61 69 6C 5F 66 69 6C 65 23 0D 0A}
	condition:
		$0 at pe.entry_point
}