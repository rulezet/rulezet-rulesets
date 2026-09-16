import "pe"
rule _PKLITE32_11__PKWARE_Inc_
{
	meta:
		description = "PKLITE32 1.1 -> PKWARE Inc."
	strings:
		$0 = {68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 00 00 00 E8 ?? ?? ?? ?? E9}
	condition:
		$0 at pe.entry_point
}