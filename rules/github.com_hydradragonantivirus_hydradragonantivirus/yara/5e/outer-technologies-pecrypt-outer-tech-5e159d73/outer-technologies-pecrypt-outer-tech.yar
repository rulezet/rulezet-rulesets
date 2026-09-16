import "pe"
rule _Outer_Technologies_PECrypt__Outer_Tech_
{
	meta:
		description = "Outer Technologies PECrypt -> Outer Tech"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 9E 00 00 00 8D BD ?? ?? ?? ?? 8B F7 33 DB AD 33 C3 2D 2F 7B 38 13 C1 C0 10 35 3C 75 94 78 AB 43 E2 EC}
	condition:
		$0 at pe.entry_point
}