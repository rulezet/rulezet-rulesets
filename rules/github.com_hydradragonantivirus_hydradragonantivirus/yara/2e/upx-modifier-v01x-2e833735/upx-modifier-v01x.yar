import "pe"
rule _UPX_Modifier_v01x_
{
	meta:
		description = "UPX Modifier v0.1x"
	strings:
		$0 = {79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? ?? 61 E9}
	condition:
		$0 at pe.entry_point
}