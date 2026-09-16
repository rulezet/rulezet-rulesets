import "pe"
rule _VisualUPX_02__emadicius_
{
	meta:
		description = "VisualUPX 0.2 -> emadicius"
	strings:
		$0 = {66 C7 05 ?? ?? ?? 00 75 07 E9 ?? FE FF FF}
	condition:
		$0 at pe.entry_point
}