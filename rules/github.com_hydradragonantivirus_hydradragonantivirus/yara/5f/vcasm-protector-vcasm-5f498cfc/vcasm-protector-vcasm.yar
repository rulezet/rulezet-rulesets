import "pe"
rule _VcAsm_Protector__VcAsm_
{
	meta:
		description = "VcAsm Protector -> VcAsm"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3}
	condition:
		$0 at pe.entry_point
}