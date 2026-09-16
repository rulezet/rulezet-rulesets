import "pe"
rule _Thinstall_Embedded_2547V2600__Jitit_
{
	meta:
		description = "Thinstall Embedded 2.547-V2.600 -> Jitit"
	strings:
		$0 = {E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00}
	condition:
		$0 at pe.entry_point
}