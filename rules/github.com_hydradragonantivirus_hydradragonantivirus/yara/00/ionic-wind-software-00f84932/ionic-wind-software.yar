import "pe"
rule _Ionic_Wind_Software_
{
	meta:
		description = "Ionic Wind Software"
	strings:
		$0 = {9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8}
	condition:
		$0 at pe.entry_point
}