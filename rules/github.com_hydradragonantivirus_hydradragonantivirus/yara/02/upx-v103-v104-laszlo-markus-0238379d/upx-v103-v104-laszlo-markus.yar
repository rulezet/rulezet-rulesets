import "pe"
rule _UPX_v103__v104__Laszlo__Markus_
{
	meta:
		description = "UPX v1.03 - v1.04 -> Laszlo & Markus"
	strings:
		$0 = {8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC}
	condition:
		$0 at pe.entry_point
}