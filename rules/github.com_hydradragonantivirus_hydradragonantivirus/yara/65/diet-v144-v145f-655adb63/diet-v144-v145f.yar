import "pe"
rule _DIET_v144_v145f_
{
	meta:
		description = "DIET v1.44, v1.45f"
	strings:
		$0 = {F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52}
	condition:
		$0 at pe.entry_point
}