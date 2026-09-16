import "pe"
rule _Nullsoft_PIMP_Install_System_v13x___Nullsoft_
{
	meta:
		description = "Nullsoft PIMP Install System v1.3x ->  Nullsoft"
	strings:
		$0 = {55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD}
	condition:
		$0 at pe.entry_point
}