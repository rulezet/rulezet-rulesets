import "pe"
rule _MEGALITE_v120a_
{
	meta:
		description = "MEGALITE v1.20a"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90}
	condition:
		$0 at pe.entry_point
}