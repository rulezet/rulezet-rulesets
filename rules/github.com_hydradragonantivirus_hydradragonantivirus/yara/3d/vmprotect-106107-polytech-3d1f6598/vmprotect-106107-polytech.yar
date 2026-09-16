rule _VMProtect_106107__PolyTech_
{
	meta:
		description = "VMProtect 1.06..1.07 -> PolyTech"
	strings:
		$0 = {9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8}
	condition:
		$0
}