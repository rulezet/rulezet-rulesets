import "pe"
rule _UPX_Shit_06__snaker_
{
	meta:
		description = "UPX Shit 0.6 -> snaker"
	strings:
		$0 = {B8 ?? ?? ?? ?? B9 15 00 00 00 80 34 08 ?? E2 FA E9}
	condition:
		$0 at pe.entry_point
}