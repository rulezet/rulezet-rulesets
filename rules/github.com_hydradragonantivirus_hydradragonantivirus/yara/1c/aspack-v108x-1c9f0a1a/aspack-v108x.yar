import "pe"
rule _ASPack_v108x_
{
	meta:
		description = "ASPack v1.08.x"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D BB 03}
	condition:
		$0 at pe.entry_point
}