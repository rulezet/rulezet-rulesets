import "pe"
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Basic__MASM32_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Basic / MASM32)"
	strings:
		$0 = {EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47}
	condition:
		$0 at pe.entry_point
}