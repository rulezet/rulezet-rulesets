import "pe"
rule _Hasp_dongle_Alladin_
{
	meta:
		description = "Hasp dongle (Alladin)"
	strings:
		$0 = {10 02 D0 51 0F ??}
	condition:
		$0 at pe.entry_point
}