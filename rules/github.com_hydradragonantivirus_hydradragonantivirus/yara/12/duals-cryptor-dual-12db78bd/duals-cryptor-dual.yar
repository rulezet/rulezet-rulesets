import "pe"
rule _Duals_Cryptor__dual_
{
	meta:
		description = "Dual's Cryptor -> dual"
	strings:
		$0 = {55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E}
		$1 = {55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}