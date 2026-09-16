import "pe"
rule _ASPack_v212__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v2.12 -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01}
		$1 = {60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}