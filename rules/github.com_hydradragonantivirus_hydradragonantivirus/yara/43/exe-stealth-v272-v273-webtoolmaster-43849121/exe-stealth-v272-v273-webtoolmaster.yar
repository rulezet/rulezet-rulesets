import "pe"
rule _EXE_Stealth_v272_v273__WebToolMaster_
{
	meta:
		description = "EXE Stealth v2.72- v2.73 -> WebToolMaster"
	strings:
		$0 = {EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20}
	condition:
		$0 at pe.entry_point
}