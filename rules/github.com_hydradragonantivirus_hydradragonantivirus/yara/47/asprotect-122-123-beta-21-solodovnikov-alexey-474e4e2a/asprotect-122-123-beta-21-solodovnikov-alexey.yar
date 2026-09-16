import "pe"
rule _ASProtect_122__123_Beta_21__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.22 - 1.23 Beta 21 -> Solodovnikov Alexey"
	strings:
		$0 = {68 01 E0 46 00 E8 01 00 00 00 C3 C3}
	condition:
		$0 at pe.entry_point
}