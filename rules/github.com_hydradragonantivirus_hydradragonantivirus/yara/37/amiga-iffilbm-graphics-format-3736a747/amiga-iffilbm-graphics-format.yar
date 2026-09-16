import "pe"
rule _Amiga_IFFILBM_Graphics_format_
{
	meta:
		description = "Amiga IFF/ILBM Graphics format"
	strings:
		$0 = {46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D 42 4D 48 44}
	condition:
		$0 at pe.entry_point
}