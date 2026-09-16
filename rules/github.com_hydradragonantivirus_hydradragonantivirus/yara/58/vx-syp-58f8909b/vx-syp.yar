import "pe"
rule _Vx_SYP_
{
	meta:
		description = "Vx: SYP"
	strings:
		$0 = {47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A}
	condition:
		$0 at pe.entry_point
}