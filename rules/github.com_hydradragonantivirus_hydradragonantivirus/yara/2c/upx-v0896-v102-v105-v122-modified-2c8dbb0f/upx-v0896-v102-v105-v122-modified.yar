import "pe"
rule _UPX_v0896__v102__v105__v122_Modified_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 Modified"
	strings:
		$0 = {01 DB 07 8B 1E 83 EE FC 11 DB 8A 07 EB B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73}
	condition:
		$0 at pe.entry_point
}