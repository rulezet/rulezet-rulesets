import "pe"
rule _EXE_Shield_v27__Exeshield_Corp_
{
	meta:
		description = "EXE Shield v2.7 -> Exeshield Corp."
	strings:
		$0 = {EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00}
	condition:
		$0 at pe.entry_point
}