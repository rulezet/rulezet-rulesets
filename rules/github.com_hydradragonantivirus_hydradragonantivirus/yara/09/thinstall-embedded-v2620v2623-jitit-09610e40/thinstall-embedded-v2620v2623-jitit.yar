import "pe"
rule _Thinstall_Embedded_V2620V2623__Jitit_
{
	meta:
		description = "Thinstall Embedded V2.620-V2.623 -> Jitit"
	strings:
		$0 = {E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00}
	condition:
		$0 at pe.entry_point
}