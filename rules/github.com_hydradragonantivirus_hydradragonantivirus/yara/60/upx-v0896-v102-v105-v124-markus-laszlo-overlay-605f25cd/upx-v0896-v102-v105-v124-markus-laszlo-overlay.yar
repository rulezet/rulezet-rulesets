import "pe"
rule _UPX_v0896__v102__v105_v124__Markus__Laszlo_overlay_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 -v1.24 -> Markus & Laszlo [overlay"
	strings:
		$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75}
	condition:
		$0 at pe.entry_point
}