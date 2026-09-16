import "pe"
rule _PESHiELD_v01b_MTE_
{
	meta:
		description = "PESHiELD v0.1b MTE"
	strings:
		$0 = {60 E8 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA}
	condition:
		$0 at pe.entry_point
}