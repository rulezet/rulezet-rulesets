import "pe"
rule _UPX_v071__v072_
{
	meta:
		description = "UPX v0.71 - v0.72"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? 60 BE 8D BE 57 83 CD}
	condition:
		$0 at pe.entry_point
}