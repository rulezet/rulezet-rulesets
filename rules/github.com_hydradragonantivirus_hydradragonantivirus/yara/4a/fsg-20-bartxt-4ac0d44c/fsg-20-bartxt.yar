import "pe"
rule _FSG_20__bartxt_
{
	meta:
		description = "FSG 2.0 - bart/xt"
	strings:
		$0 = {87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9}
	condition:
		$0 at pe.entry_point
}