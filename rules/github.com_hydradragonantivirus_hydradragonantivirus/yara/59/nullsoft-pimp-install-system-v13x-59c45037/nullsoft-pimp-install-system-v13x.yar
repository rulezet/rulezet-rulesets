import "pe"
rule _Nullsoft_PIMP_Install_System_v13x_
{
	meta:
		description = "Nullsoft PIMP Install System v1.3x"
	strings:
		$0 = {83 EC 5C 53 55 56 57 FF}
	condition:
		$0 at pe.entry_point
}