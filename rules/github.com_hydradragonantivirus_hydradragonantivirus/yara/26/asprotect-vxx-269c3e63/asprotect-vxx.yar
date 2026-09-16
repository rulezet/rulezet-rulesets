import "pe"
rule _ASProtect_vxx_
{
	meta:
		description = "ASProtect vx.x"
	strings:
		$0 = {60 90 5D 03}
		$1 = {60 E8 01 90 5D 81 ED BB 03 DD 2B}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}