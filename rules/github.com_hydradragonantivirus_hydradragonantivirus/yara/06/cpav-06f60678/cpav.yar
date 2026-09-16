import "pe"
rule _CPAV_
{
	meta:
		description = "CPAV"
	strings:
		$0 = {E8 ?? ?? 4D 5A B1 01 93 01 00 00 02}
	condition:
		$0 at pe.entry_point
}