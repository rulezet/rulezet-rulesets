import "pe"
rule _Adys_Glue_v010_
{
	meta:
		description = "Ady`s Glue v0.10"
	strings:
		$0 = {2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F}
	condition:
		$0 at pe.entry_point
}