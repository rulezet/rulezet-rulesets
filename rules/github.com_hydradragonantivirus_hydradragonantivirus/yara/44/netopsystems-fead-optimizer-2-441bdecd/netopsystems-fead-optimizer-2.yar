import "pe"
rule _Netopsystems_FEAD_Optimizer_2_
{
	meta:
		description = "Netopsystems FEAD Optimizer 2"
	strings:
		$0 = {50 E8 00 00 00 00 5B 81 EB A2 01 00 00 B9 ?? ?? 01 00 2B D9 8B F3 81 EB 00 ?? ?? 00 8B FB 81 EB 00 10 00 00 57 51 56 E8 89 FE FF FF 83 C4 0C 8B AB C0 00 00 00 8D 2C 2B 4D 8A 4D 00 80 F9 CC 74}
	condition:
		$0 at pe.entry_point
}