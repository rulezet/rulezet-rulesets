import "pe"
rule _Free_Pascal_106_
{
	meta:
		description = "Free Pascal 1.06"
	strings:
		$0 = {C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}