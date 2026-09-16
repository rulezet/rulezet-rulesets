rule _ASPack_v211d_
{
	meta:
		description = "ASPack v2.11d"
	strings:
		$0 = {60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB ED FF FF FF 03 DD 81}
	condition:
		$0 at entrypoint
}