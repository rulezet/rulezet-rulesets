import "pe"
rule _MSLRH_V031__emadicius_
{
	meta:
		description = "[MSLRH] V0.31 -> emadicius"
	strings:
		$0 = {60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1}
	condition:
		$0 at pe.entry_point
}