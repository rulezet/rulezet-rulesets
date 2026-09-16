import "pe"
rule _Spirit_15_
{
	meta:
		description = "Spirit 1.5"
	strings:
		$0 = {E9 00 00 5B 24 55 50 44 FB 32 2E 31 5D}
	condition:
		$0 at pe.entry_point
}