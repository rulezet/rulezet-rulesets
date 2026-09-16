import "pe"
rule _SCRAM_vC5_
{
	meta:
		description = "SCRAM! vC5"
	strings:
		$0 = {B8 ?? ?? 50 9D 9C 58 25 ?? ?? 75 ?? BA ?? ?? B4 09 CD 21 CD 20}
	condition:
		$0 at pe.entry_point
}