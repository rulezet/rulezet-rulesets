import "pe"
rule _Adys_Glue_110_
{
	meta:
		description = "Ady's Glue 1.10"
	strings:
		$0 = {2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC}
	condition:
		$0 at pe.entry_point
}