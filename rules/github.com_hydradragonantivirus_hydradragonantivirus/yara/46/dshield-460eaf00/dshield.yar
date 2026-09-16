import "pe"
rule _DSHIELD_
{
	meta:
		description = "DSHIELD"
	strings:
		$0 = {06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E}
	condition:
		$0 at pe.entry_point
}