import "pe"
rule _unknown__jac_
{
	meta:
		description = "unknown -> jac"
	strings:
		$0 = {55 89 E5 B9 00 80 00 00 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 31 C2 66 01 C2 C1 C2 07 E2 F1 50 E8 91 FF FF FF C9 C3}
	condition:
		$0 at pe.entry_point
}