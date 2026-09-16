import "pe"
rule _Vx_Trivial25_
{
	meta:
		description = "Vx: Trivial.25"
	strings:
		$0 = {B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD}
	condition:
		$0 at pe.entry_point
}