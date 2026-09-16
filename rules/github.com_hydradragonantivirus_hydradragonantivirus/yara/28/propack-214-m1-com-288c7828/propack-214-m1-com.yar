import "pe"
rule _ProPack_214_m1_COM_
{
	meta:
		description = "ProPack 2.14 -m1 [COM]"
	strings:
		$0 = {83 EC 10 8B EC BE FA 02 FC E8 41 00 05 00 01 8B C8 E8 39 00 8B D0 03 C6 05 06 00 8B F8 E8 2D 00 AD 88 66 0A 32 E4 89 76 00 8B F7 03 C1 8B F8 3B FE 76 0E}
	condition:
		$0 at pe.entry_point
}