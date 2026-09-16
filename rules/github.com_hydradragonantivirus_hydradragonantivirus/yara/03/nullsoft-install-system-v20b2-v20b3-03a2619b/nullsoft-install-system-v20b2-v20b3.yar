import "pe"
rule _Nullsoft_Install_System_v20b2_v20b3_
{
	meta:
		description = "Nullsoft Install System v2.0b2, v2.0b3"
	strings:
		$0 = {55 8B EC 81 EC ?? ?? 56 57 6A BE 59 8D}
	condition:
		$0 at pe.entry_point
}