import "pe"
rule _REC_C0ded_by_ROSE_
{
	meta:
		description = "REC, C0ded by ROSE"
	strings:
		$0 = {06 1E 0E 0E 07 1F B4 30 CD 21 86 E0 3D 00 03 73 ?? CD 20 EB}
	condition:
		$0 at pe.entry_point
}