import "pe"
rule _FSG_v20__bartxt_
{
	meta:
		description = "FSG v2.0 -> bart/xt"
	strings:
		$0 = {87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13}
	condition:
		$0 at pe.entry_point
}