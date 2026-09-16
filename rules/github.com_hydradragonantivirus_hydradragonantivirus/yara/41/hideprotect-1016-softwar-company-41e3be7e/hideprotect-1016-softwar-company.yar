import "pe"
rule _HideProtect_1016__SoftWar_Company_
{
	meta:
		description = "Hide&Protect 1.016 -> SoftWar Company"
	strings:
		$0 = {90 90 90 E9 D8 ?? 05 00 95 ?? 53 00 95 4A 50 00}
	condition:
		$0 at pe.entry_point
}