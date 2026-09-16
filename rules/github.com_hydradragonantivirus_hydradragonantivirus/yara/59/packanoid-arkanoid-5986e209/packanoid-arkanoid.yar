import "pe"
rule _Packanoid__Arkanoid_
{
	meta:
		description = "Packanoid -> Arkanoid"
	strings:
		$0 = {BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8}
	condition:
		$0 at pe.entry_point
}