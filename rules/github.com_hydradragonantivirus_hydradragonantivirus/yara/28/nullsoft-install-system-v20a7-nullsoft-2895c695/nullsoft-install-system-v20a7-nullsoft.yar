import "pe"
rule _Nullsoft_Install_System_v20a7__Nullsoft_
{
	meta:
		description = "Nullsoft Install System v2.0a7 -> Nullsoft"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 BC 80 40 00}
	condition:
		$0 at pe.entry_point
}