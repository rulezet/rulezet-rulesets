import "pe"
rule _EXE_Stealth_v276__WebToolMaster_
{
	meta:
		description = "EXE Stealth v2.76 -> WebToolMaster"
	strings:
		$0 = {EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41}
	condition:
		$0 at pe.entry_point
}