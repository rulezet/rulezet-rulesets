import "pe"
rule _SimplePack_V11XV12X_Method2__bagie_
{
	meta:
		description = "SimplePack V1.1X-V1.2X (Method2) -> bagie"
	strings:
		$0 = {4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00}
	condition:
		$0 at pe.entry_point
}