import "pe"
rule _AdFlt2_
{
	meta:
		description = "AdFlt2"
	strings:
		$0 = {68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD}
	condition:
		$0 at pe.entry_point
}