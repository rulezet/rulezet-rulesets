import "pe"
rule _Nullsoft_PIMP_Install_System_v1x___Nullsoft_
{
	meta:
		description = "Nullsoft PIMP Install System v1.x ->  Nullsoft"
	strings:
		$0 = {83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}