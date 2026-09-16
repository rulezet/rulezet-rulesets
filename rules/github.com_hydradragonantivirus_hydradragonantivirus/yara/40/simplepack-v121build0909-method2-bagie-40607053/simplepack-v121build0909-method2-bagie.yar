import "pe"
rule _SimplePack_V121build0909_Method2__bagie_
{
	meta:
		description = "SimplePack V1.21.build.09.09 (Method2) -> bagie"
	strings:
		$0 = {4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04}
	condition:
		$0 at pe.entry_point
}