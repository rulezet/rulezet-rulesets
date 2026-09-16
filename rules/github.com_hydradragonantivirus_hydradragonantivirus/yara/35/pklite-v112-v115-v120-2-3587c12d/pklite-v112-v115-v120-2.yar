import "pe"
rule _PKLITE_v112_v115_v120_2_
{
	meta:
		description = "PKLITE v1.12, v1.15, v1.20 (2)"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 3B C4 73}
	condition:
		$0 at pe.entry_point
}