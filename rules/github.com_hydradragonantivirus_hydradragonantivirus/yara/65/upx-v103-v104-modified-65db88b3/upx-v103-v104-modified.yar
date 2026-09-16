import "pe"
rule _UPX_v103__v104_Modified_
{
	meta:
		description = "UPX v1.03 - v1.04 Modified"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at pe.entry_point
}