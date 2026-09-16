import "pe"
rule _Vx_NcuLi1688_
{
	meta:
		description = "Vx: Ncu-Li.1688"
	strings:
		$0 = {0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8}
	condition:
		$0 at pe.entry_point
}