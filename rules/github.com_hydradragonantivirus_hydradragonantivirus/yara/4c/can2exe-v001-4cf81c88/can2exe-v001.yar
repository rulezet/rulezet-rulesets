import "pe"
rule _CAN2EXE_v001_
{
	meta:
		description = "CAN2EXE v0.01"
	strings:
		$0 = {26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9}
	condition:
		$0 at pe.entry_point
}