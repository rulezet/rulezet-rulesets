import "pe"
rule _FSG_v10__dulekxt_
{
	meta:
		description = "FSG v1.0 -> dulek/xt"
	strings:
		$0 = {BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B}
	condition:
		$0 at pe.entry_point
}