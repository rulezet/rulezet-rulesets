import "pe"
rule _Fusion_V10__jaNooNi_
{
	meta:
		description = "Fusion V1.0 -> jaNooNi"
	strings:
		$0 = {68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00}
	condition:
		$0 at pe.entry_point
}