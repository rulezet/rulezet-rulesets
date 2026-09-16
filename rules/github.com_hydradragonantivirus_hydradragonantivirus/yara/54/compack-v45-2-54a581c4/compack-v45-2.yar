import "pe"
rule _COMPACK_v45_2_
{
	meta:
		description = "COMPACK v4.5 (2)"
	strings:
		$0 = {BE ?? ?? E8 ?? ?? 5D 83 ?? ?? 55 50 53 51 52 0E 07 0E 1F 8B CE}
	condition:
		$0 at pe.entry_point
}