import "pe"
rule _Frusion__biff_
{
	meta:
		description = "Frusion -> biff"
	strings:
		$0 = {83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14}
	condition:
		$0 at pe.entry_point
}