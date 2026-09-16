import "pe"
rule _Vx_Danish_tiny_
{
	meta:
		description = "Vx: Danish tiny"
	strings:
		$0 = {33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21}
	condition:
		$0 at pe.entry_point
}