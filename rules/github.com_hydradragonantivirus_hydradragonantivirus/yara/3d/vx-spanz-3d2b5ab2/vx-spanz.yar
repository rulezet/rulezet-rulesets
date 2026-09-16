import "pe"
rule _Vx_Spanz_
{
	meta:
		description = "Vx: Spanz"
	strings:
		$0 = {E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84}
	condition:
		$0 at pe.entry_point
}